using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HelloWorldSSO.Authentication;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Moq;

namespace HelloWorldSSO.Tests;

public class SsoTests
{
    private const string Tenant = "11111111-1111-1111-1111-111111111111";

    private static string Metadata(string entityId = "https://idp.example.com/meta", string sso = "https://idp.example.com/sso")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=idp", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var b64 = Convert.ToBase64String(cert.RawData);
        return $"""
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entityId}">
              <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>{b64}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso}" />
              </IDPSSODescriptor>
            </EntityDescriptor>
            """;
    }

    private static ApplicationDbContext NewDb() =>
        new(new DbContextOptionsBuilder<ApplicationDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);

    [Fact]
    public void Parser_accepts_valid_metadata()
    {
        var info = SamlMetadataParser.Parse(Metadata());
        Assert.Equal("https://idp.example.com/meta", info.EntityId);
        Assert.Single(info.SigningCertificates);
    }

    [Theory]
    [InlineData("<not-xml")]
    [InlineData("<!DOCTYPE x [<!ENTITY a \"b\">]><EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"x\"/>")]
    public void Parser_rejects_bad_xml(string xml) => Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse(xml));

    [Fact]
    public void Parser_rejects_http_sso_url() =>
        Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse(Metadata(sso: "http://idp.example.com/sso")));

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("169.254.169.254", true)]
    [InlineData("192.168.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("::ffff:10.0.0.1", true)]
    [InlineData("8.8.8.8", false)]
    public void Ssrf_guard_blocks_private_addresses(string ip, bool blocked) =>
        Assert.Equal(blocked, SafeMetadataFetcher.IsBlocked(IPAddress.Parse(ip)));

    [Fact]
    public async Task Fetcher_rejects_non_https_and_literal_private()
    {
        var fetcher = new SafeMetadataFetcher(new Mock<IHttpClientFactory>().Object);
        await Assert.ThrowsAsync<SamlMetadataException>(() => fetcher.FetchAsync("http://idp.example.com/m"));
        await Assert.ThrowsAsync<SamlMetadataException>(() => fetcher.FetchAsync("https://127.0.0.1/m"));
    }

    [Fact]
    public async Task Entra_tenant_unique_and_activation_requires_test()
    {
        using var db = NewDb();
        var svc = new SsoConfigurationService(db, null!);
        var a = Guid.NewGuid(); var b = Guid.NewGuid();
        var tid = Guid.NewGuid().ToString();
        var cfg = await svc.SaveEntraAsync(a, tid);
        await Assert.ThrowsAsync<SsoConfigurationException>(() => svc.SaveEntraAsync(b, tid));
        await Assert.ThrowsAsync<SsoConfigurationException>(() => svc.SaveEntraAsync(a, "not-a-guid"));
        await Assert.ThrowsAsync<SsoConfigurationException>(() => svc.ActivateAsync(a, cfg.Id));
        await svc.MarkTestSucceededAsync(cfg);
        await svc.ActivateAsync(a, cfg.Id);
        Assert.Equal(SsoStatus.Active, cfg.Status);
        // Editing an active configuration creates a separate draft; the active one stays live.
        var draft = await svc.SaveEntraAsync(a, Guid.NewGuid().ToString());
        Assert.NotEqual(cfg.Id, draft.Id);
        Assert.Equal(SsoStatus.Active, cfg.Status);
    }

    private static async Task<(TenantAuthorizationService Svc, Customer C, SsoConfiguration Cfg, ApplicationDbContext Db)> Arrange(string status, string role = UserRoles.User)
    {
        var db = NewDb();
        var customers = new CustomerService(db);
        var sso = new SsoConfigurationService(db, null!);
        var c = await customers.CreateAsync("Contoso", "contoso");
        var cfg = await sso.SaveEntraAsync(c.Id, Tenant);
        cfg.Status = status;
        await db.SaveChangesAsync();
        await customers.InviteUserAsync(c.Id, "jane@contoso.com", role, AuthenticationTypes.EntraOidc);
        var env = new Mock<IHostEnvironment>(); env.Setup(e => e.EnvironmentName).Returns("Production");
        return (new TenantAuthorizationService(db, sso, customers, env.Object), c, cfg, db);
    }

    private static ClaimsPrincipal Entra(string tid, string oid = "22222222-2222-2222-2222-222222222222") =>
        new(new ClaimsIdentity([new Claim("tid", tid), new Claim("oid", oid), new Claim("preferred_username", "jane@contoso.com")], "x"));

    private static AuthenticationProperties Props(Guid customer, bool test = false)
    {
        var p = new AuthenticationProperties();
        p.Items[AppClaims.PropType] = AuthenticationTypes.EntraOidc;
        p.Items[AppClaims.PropCustomer] = customer.ToString();
        if (test) p.Items[AppClaims.PropTest] = "1";
        return p;
    }

    [Fact]
    public async Task Active_tenant_and_invited_user_is_authorized_and_linked()
    {
        var (svc, c, _, db) = await Arrange(SsoStatus.Active);
        var r = await svc.AuthorizeAsync(Entra(Tenant), Props(c.Id));
        Assert.True(r.Succeeded);
        Assert.Equal(c.Id.ToString(), r.Principal!.FindFirst(AppClaims.CustomerId)!.Value);
        Assert.Contains(db.CustomerUsers, u => u.ExternalUserId == Tenant + ":22222222-2222-2222-2222-222222222222");
    }

    [Fact]
    public async Task Unapproved_tenant_is_denied()
    {
        var (svc, c, _, _) = await Arrange(SsoStatus.Active);
        Assert.False((await svc.AuthorizeAsync(Entra("33333333-3333-3333-3333-333333333333"), Props(c.Id))).Succeeded);
    }

    [Fact]
    public async Task Flow_not_started_by_app_is_denied()
    {
        var (svc, _, _, _) = await Arrange(SsoStatus.Active);
        Assert.False((await svc.AuthorizeAsync(Entra(Tenant), new AuthenticationProperties())).Succeeded);
    }

    [Fact]
    public async Task Inactive_config_only_allows_admin_test_login()
    {
        var (svc, c, _, _) = await Arrange(SsoStatus.Pending, UserRoles.User);
        Assert.False((await svc.AuthorizeAsync(Entra(Tenant), Props(c.Id, test: true))).Succeeded);

        var (svc2, c2, cfg2, _) = await Arrange(SsoStatus.Pending, UserRoles.Admin);
        Assert.False((await svc2.AuthorizeAsync(Entra(Tenant), Props(c2.Id))).Succeeded);
        Assert.True((await svc2.AuthorizeAsync(Entra(Tenant), Props(c2.Id, test: true))).Succeeded);
        Assert.Equal(SsoStatus.Testing, cfg2.Status);
        Assert.NotNull(cfg2.LastTestSucceededAt);
    }

    [Fact]
    public async Task Suspended_customer_is_denied()
    {
        var (svc, c, _, db) = await Arrange(SsoStatus.Active);
        c.Status = CustomerStatus.Suspended;
        await db.SaveChangesAsync();
        Assert.False((await svc.AuthorizeAsync(Entra(Tenant), Props(c.Id))).Succeeded);
    }
}
