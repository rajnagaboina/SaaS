using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.WebSso;

namespace HelloWorldSSO.Authentication;

public static class SamlAuthentication
{
    /// <summary>Path under which Sustainsys.Saml2 serves SP metadata (GET) and the ACS (/Acs).</summary>
    public const string ModulePath = "/Saml2";

    public static string SpEntityId(IConfiguration configuration) =>
        configuration["Saml:EntityId"] is { Length: > 0 } configured
            ? configured
            : PublicBaseUrl(configuration) + ModulePath;

    public static string AcsUrl(IConfiguration configuration) => PublicBaseUrl(configuration) + ModulePath + "/Acs";

    public static string MetadataUrl(IConfiguration configuration) => PublicBaseUrl(configuration) + ModulePath;

    public static string PublicBaseUrl(IConfiguration configuration) =>
        (configuration["App:PublicBaseUrl"] ?? "https://localhost:5001").TrimEnd('/');

    /// <summary>
    /// Registers the SAML 2.0 handler. No identity providers are configured statically; each
    /// customer's IdP is resolved from the database per request by <see cref="SamlIdentityProviderStore"/>.
    /// </summary>
    public static AuthenticationBuilder AddSamlAuthentication(this AuthenticationBuilder builder, IConfiguration configuration)
    {
        builder.Services.AddSingleton<SamlIdentityProviderStore>();

        builder.AddSaml2(AuthSchemes.Saml, "SAML 2.0", options =>
        {
            options.SignInScheme = AuthSchemes.External;
            options.SPOptions.EntityId = new EntityId(SpEntityId(configuration));
            options.SPOptions.ModulePath = ModulePath;
            options.SPOptions.PublicOrigin = new Uri(PublicBaseUrl(configuration) + "/");
            options.SPOptions.ReturnUrl = new Uri(PublicBaseUrl(configuration) + "/auth/complete");
            // Sustainsys rejects responses where neither the Response nor the Assertion is signed by
            // one of the IdP's configured certificates; WantAssertionsSigned is left at its default
            // (false) so IdPs that sign only the outer Response still work.
        });

        builder.Services.AddOptions<Saml2Options>(AuthSchemes.Saml)
            .Configure<SamlIdentityProviderStore>((options, store) =>
            {
                options.Notifications.GetIdentityProvider = (entityId, _, saml2Options) =>
                    store.Get(entityId.Id, saml2Options.SPOptions)
                    ?? throw new InvalidOperationException(
                        $"Identity provider '{entityId.Id}' is not configured for any organization.");

                // SignInCommand resolves the IdP through this notification rather than GetIdentityProvider.
                options.Notifications.SelectIdentityProvider = (entityId, _) =>
                    entityId is null ? null : store.Get(entityId.Id, options.SPOptions);
            });

        return builder;
    }
}

/// <summary>
/// Supplies Sustainsys.Saml2 with customer IdP definitions built from validated, normalized
/// database records (never by fetching metadata at sign-in time). Only configurations in the
/// Testing or Active state are exposed; which flows may use which state is enforced afterwards
/// by <see cref="TenantAuthorizationService"/>.
/// </summary>
public class SamlIdentityProviderStore(IServiceScopeFactory scopeFactory, ILogger<SamlIdentityProviderStore> logger)
{
    private sealed record Entry(Guid ConfigurationId, Guid CustomerId, string EntityId, string SsoUrl, string Binding, X509Certificate2[] Certificates);

    private readonly ConcurrentDictionary<string, Entry> _cache = new(StringComparer.Ordinal);

    public void Invalidate(string? entityId)
    {
        if (entityId is not null)
            _cache.TryRemove(entityId, out _);
    }

    public IdentityProvider? Get(string entityId, SPOptions spOptions)
    {
        var entry = _cache.TryGetValue(entityId, out var cached) ? cached : Load(entityId);
        if (entry is null)
            return null;

        var idp = new IdentityProvider(new EntityId(entry.EntityId), spOptions)
        {
            AllowUnsolicitedAuthnResponse = false,
            SingleSignOnServiceUrl = new Uri(entry.SsoUrl),
            Binding = entry.Binding == "HttpPost" ? Saml2BindingType.HttpPost : Saml2BindingType.HttpRedirect,
        };
        foreach (var cert in entry.Certificates)
            idp.SigningKeys.AddConfiguredKey(cert);
        // Must be last: setting LoadMetadata validates the IdP immediately.
        idp.LoadMetadata = false;
        return idp;
    }

    private Entry? Load(string entityId)
    {
        // Sustainsys notifications are synchronous.
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var configs = db.SsoConfigurations.AsNoTracking()
            .Where(c => c.AuthenticationType == AuthenticationTypes.Saml
                        && c.SamlEntityId == entityId
                        && (c.Status == SsoStatus.Testing || c.Status == SsoStatus.Active))
            .ToList();

        if (configs.Count != 1)
        {
            // Uniqueness is enforced when configurations are saved; two live matches means
            // something is wrong, so fail closed rather than pick one.
            if (configs.Count > 1)
                logger.LogError("SAML entity ID {EntityId} is used by {Count} live configurations; refusing to use it.", entityId, configs.Count);
            return null;
        }

        var config = configs[0];
        var certs = (config.SamlSigningCertificates ?? "")
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(b64 => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(b64)))
            .ToArray();

        var entry = new Entry(config.Id, config.CustomerId, entityId, config.SamlSsoUrl!, config.SamlSsoBinding ?? "HttpRedirect", certs);
        _cache[entityId] = entry;
        return entry;
    }
}
