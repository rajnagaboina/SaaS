using System.Security.Cryptography.X509Certificates;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Metadata;

namespace HelloWorldSSO.Authentication;

public static class SamlAuthentication
{
    public const string Scheme = Saml2Defaults.Scheme;

    public static AuthenticationBuilder AddSaml(this AuthenticationBuilder auth, IConfiguration config)
    {
        auth.AddSaml2(Scheme, options =>
        {
            var baseUrl = (config["App:BaseUrl"] ?? "https://localhost:7119").TrimEnd('/');
            options.SignInScheme = SessionAuthentication.CookieScheme;
            options.SPOptions.EntityId = new EntityId($"{baseUrl}/Saml2");
            options.SPOptions.ReturnUrl = new Uri($"{baseUrl}/");
            // Identity providers are per-customer and loaded from the database on demand.
            options.Notifications.GetIdentityProvider = (entityId, _, opts) =>
                LoadIdentityProvider(entityId.Id, opts.SPOptions);
        });
        return auth;
    }

    internal static IdentityProvider? LoadIdentityProvider(string entityId, Sustainsys.Saml2.Configuration.SPOptions sp)
    {
        var services = ServiceProviderAccessor.Root;
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var configs = db.SsoConfigurations
            .Where(c => c.AuthenticationType == AuthenticationTypes.Saml && c.SamlEntityId == entityId && c.Status != SsoStatus.Disabled)
            .ToList();
        var cfg = configs.FirstOrDefault(c => c.Status == SsoStatus.Active) ?? configs.FirstOrDefault();
        if (cfg?.SamlSingleSignOnUrl is null || cfg.SamlSigningCertificates is null) return null;

        var idp = new IdentityProvider(new EntityId(entityId), sp)
        {
            SingleSignOnServiceUrl = new Uri(cfg.SamlSingleSignOnUrl),
            Binding = Sustainsys.Saml2.WebSso.Saml2BindingType.HttpRedirect,
            AllowUnsolicitedAuthnResponse = false,
            LoadMetadata = false,
        };
        foreach (var cert in cfg.SamlSigningCertificates.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            idp.SigningKeys.AddConfiguredKey(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(cert)));
        return idp;
    }
}

public static class ServiceProviderAccessor
{
    public static IServiceProvider Root { get; set; } = null!;
}
