using System.Security.Claims;
using HelloWorldSSO.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace HelloWorldSSO.Authentication;

/// <summary>Builds challenges that start an external sign-in for a specific flow.</summary>
public static class SignInRequests
{
    public const string CompletionPath = "/auth/complete";

    public static ChallengeResult ForConfiguration(SsoConfiguration config, string flow, IDictionary<string, string?>? extra = null)
    {
        return config.AuthenticationType == AuthenticationTypes.Saml
            ? Saml(config.SamlEntityId!, flow, Merge(extra, AuthItems.ConfigurationId, config.Id.ToString()))
            : Entra(config.EntraTenantId, flow, Merge(extra, AuthItems.ConfigurationId, config.Id.ToString()));
    }

    public static ChallengeResult Entra(string? tenantId, string flow, IDictionary<string, string?>? extra = null)
    {
        var properties = Properties(flow, AuthSchemes.Oidc, extra);
        if (tenantId is not null)
            properties.Items[AuthItems.EntraTenant] = tenantId;
        return new ChallengeResult(AuthSchemes.Oidc, properties);
    }

    public static ChallengeResult Saml(string idpEntityId, string flow, IDictionary<string, string?>? extra = null)
    {
        var properties = Properties(flow, AuthSchemes.Saml, extra);
        properties.Items[AuthItems.SamlIdp] = idpEntityId;
        return new ChallengeResult(AuthSchemes.Saml, properties);
    }

    private static AuthenticationProperties Properties(string flow, string scheme, IDictionary<string, string?>? extra)
    {
        var properties = new AuthenticationProperties { RedirectUri = CompletionPath };
        properties.Items[AuthItems.Flow] = flow;
        properties.Items[AuthItems.Scheme] = scheme;
        foreach (var (key, value) in extra ?? new Dictionary<string, string?>())
            properties.Items[key] = value;
        return properties;
    }

    private static Dictionary<string, string?> Merge(IDictionary<string, string?>? extra, string key, string value) =>
        new(extra ?? new Dictionary<string, string?>()) { [key] = value };
}

public static class ClaimsPrincipalExtensions
{
    public static Guid GetCustomerId(this ClaimsPrincipal user) =>
        Guid.Parse(user.FindFirst(AppClaims.CustomerId)?.Value ?? throw new InvalidOperationException("No customer in session."));

    public static Guid GetUserId(this ClaimsPrincipal user) =>
        Guid.Parse(user.FindFirst(AppClaims.UserId)?.Value ?? throw new InvalidOperationException("No user in session."));

    public static string? GetCustomerName(this ClaimsPrincipal user) => user.FindFirst(AppClaims.CustomerName)?.Value;

    public static string? GetEmail(this ClaimsPrincipal user) => user.FindFirst(AppClaims.Email)?.Value;
}
