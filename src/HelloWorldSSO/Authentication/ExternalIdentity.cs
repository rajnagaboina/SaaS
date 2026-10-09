using System.Security.Claims;
using HelloWorldSSO.Models;
using Microsoft.Identity.Web;

namespace HelloWorldSSO.Authentication;

/// <summary>
/// A validated identity from an external provider, mapped explicitly from protocol-specific
/// claims into the fields the application relies on.
/// </summary>
/// <param name="Provider"><see cref="AuthenticationTypes.EntraOidc"/> or <see cref="AuthenticationTypes.Saml"/>.</param>
/// <param name="Issuer">Entra tenant ID, or the SAML IdP entity ID.</param>
/// <param name="ExternalUserId">Stable account-linking key; never the email address.</param>
public record ExternalIdentity(string Provider, string Issuer, string ExternalUserId, string Email, string DisplayName)
{
    private const string SamlEmail = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";

    public static ExternalIdentity? FromPrincipal(ClaimsPrincipal principal, string scheme)
    {
        return scheme switch
        {
            AuthSchemes.Oidc => FromEntra(principal),
            AuthSchemes.Saml => FromSaml(principal),
            _ => null,
        };
    }

    private static ExternalIdentity? FromEntra(ClaimsPrincipal principal)
    {
        var tenantId = principal.GetTenantId();
        var objectId = principal.GetObjectId();
        if (!Guid.TryParse(tenantId, out _) || !Guid.TryParse(objectId, out _))
            return null;

        var email = principal.FindFirst("email")?.Value
                    ?? principal.FindFirst(ClaimTypes.Email)?.Value
                    ?? principal.FindFirst("preferred_username")?.Value
                    ?? principal.FindFirst(ClaimTypes.Upn)?.Value
                    ?? "";
        var name = principal.FindFirst("name")?.Value ?? principal.Identity?.Name ?? email;

        return new ExternalIdentity(AuthenticationTypes.EntraOidc, tenantId!.ToLowerInvariant(),
            $"{tenantId!.ToLowerInvariant()}:{objectId!.ToLowerInvariant()}", email, name);
    }

    private static ExternalIdentity? FromSaml(ClaimsPrincipal principal)
    {
        var nameId = principal.FindFirst(ClaimTypes.NameIdentifier);
        if (nameId is null || string.IsNullOrEmpty(nameId.Value) || string.IsNullOrEmpty(nameId.Issuer)
            || nameId.Issuer == ClaimsIdentity.DefaultIssuer)
            return null;

        // The claim issuer is the validated assertion issuer (the IdP entity ID).
        var issuer = nameId.Issuer;
        var email = principal.FindFirst(ClaimTypes.Email)?.Value
                    ?? principal.FindFirst(SamlEmail)?.Value
                    ?? principal.FindFirst("email")?.Value
                    ?? principal.FindFirst("mail")?.Value
                    ?? (nameId.Value.Contains('@') ? nameId.Value : "");
        var given = principal.FindFirst(ClaimTypes.GivenName)?.Value;
        var surname = principal.FindFirst(ClaimTypes.Surname)?.Value;
        var name = principal.FindFirst("http://schemas.microsoft.com/identity/claims/displayname")?.Value
                   ?? principal.FindFirst(ClaimTypes.Name)?.Value
                   ?? (given is not null || surname is not null ? $"{given} {surname}".Trim() : null)
                   ?? (email.Length > 0 ? email : nameId.Value);

        return new ExternalIdentity(AuthenticationTypes.Saml, issuer, $"{issuer}|{nameId.Value}", email, name);
    }
}
