using System.Security.Claims;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Authentication;

public record TenantAuthorizationResult(bool Succeeded, ClaimsPrincipal? Principal, string? Reason)
{
    public static TenantAuthorizationResult Fail(string reason) => new(false, null, reason);
}

/// <summary>
/// Single authorization gate used by every login protocol. Takes an externally authenticated principal and
/// returns an application principal built only from database state, or a denial.
/// </summary>
public class TenantAuthorizationService(ApplicationDbContext db, SsoConfigurationService sso, CustomerService customers, IHostEnvironment env)
{
    public async Task<TenantAuthorizationResult> AuthorizeAsync(ClaimsPrincipal external, AuthenticationProperties props)
    {
        props.Items.TryGetValue(AppClaims.PropType, out var type);
        props.Items.TryGetValue(AppClaims.PropCustomer, out var customerIdText);
        var isTest = props.Items.TryGetValue(AppClaims.PropTest, out var t) && t == "1";

        // Rejects IdP-initiated / unsolicited responses and any flow not started from our login page.
        if (type is null || !Guid.TryParse(customerIdText, out var customerId))
            return await DenyAsync(null, "Sign-in was not started from this application.");

        var customer = await customers.GetAsync(customerId);
        if (customer is null || customer.Status != CustomerStatus.Active)
            return await DenyAsync(customerId, "Organization is not active.");

        string? externalId, email, issuerOrTenant;
        switch (type)
        {
            case AuthenticationTypes.EntraOidc:
                var tid = First(external, "tid", "http://schemas.microsoft.com/identity/claims/tenantid");
                var oid = First(external, "oid", "http://schemas.microsoft.com/identity/claims/objectidentifier");
                if (tid is null || oid is null) return await DenyAsync(customerId, "Token is missing tenant or object id.");
                externalId = $"{tid.ToLowerInvariant()}:{oid.ToLowerInvariant()}";
                email = First(external, "preferred_username", "email", ClaimTypes.Email, ClaimTypes.Upn);
                issuerOrTenant = tid.ToLowerInvariant();
                break;
            case AuthenticationTypes.Saml:
                var nameId = external.FindFirst(ClaimTypes.NameIdentifier);
                if (nameId is null || string.IsNullOrEmpty(nameId.Value) || string.IsNullOrEmpty(nameId.Issuer))
                    return await DenyAsync(customerId, "SAML assertion has no subject.");
                externalId = $"{nameId.Issuer}|{nameId.Value}";
                email = First(external, ClaimTypes.Email, "email", "mail")
                    ?? (nameId.Value.Contains('@') ? nameId.Value : null);
                issuerOrTenant = nameId.Issuer;
                break;
            case AuthenticationTypes.Dev when env.IsDevelopment():
                externalId = null;
                email = First(external, ClaimTypes.Email);
                issuerOrTenant = null;
                break;
            default:
                return await DenyAsync(customerId, "Unsupported authentication type.");
        }

        // The identity provider must match one of this customer's configurations.
        SsoConfiguration? config = null;
        if (type != AuthenticationTypes.Dev)
        {
            var configs = (await sso.ListAsync(customerId))
                .Where(c => c.AuthenticationType == type && c.Status != SsoStatus.Disabled
                    && (type == AuthenticationTypes.EntraOidc
                        ? string.Equals(c.EntraTenantId, issuerOrTenant, StringComparison.OrdinalIgnoreCase)
                        : c.SamlEntityId == issuerOrTenant))
                .ToList();
            config = configs.FirstOrDefault(c => c.Status == SsoStatus.Active) ?? configs.FirstOrDefault();
            if (config is null) return await DenyAsync(customerId, "Identity provider is not approved for this organization.");
        }

        var provider = type;
        CustomerUser? user = null;
        if (externalId is not null)
        {
            user = await db.CustomerUsers.FirstOrDefaultAsync(u => u.CustomerId == customerId
                && u.IdentityProvider == provider && u.ExternalUserId == externalId);
            if (user is null && !string.IsNullOrEmpty(email))
            {
                // Link a pending invitation (no external identity yet) by e-mail, only within the approved IdP.
                var lowered = email.ToLowerInvariant();
                user = await db.CustomerUsers.FirstOrDefaultAsync(u => u.CustomerId == customerId
                    && u.IdentityProvider == provider && u.ExternalUserId == "" && u.Email.ToLower() == lowered);
                if (user is not null)
                {
                    user.ExternalUserId = externalId;
                    await db.SaveChangesAsync();
                }
            }
        }
        else if (!string.IsNullOrEmpty(email))
        {
            var lowered = email.ToLowerInvariant();
            user = await db.CustomerUsers.FirstOrDefaultAsync(u => u.CustomerId == customerId && u.Email.ToLower() == lowered);
        }
        if (user is null || user.Status != "Active")
            return await DenyAsync(customerId, "User is not authorized for this organization.");

        if (config is not null && config.Status != SsoStatus.Active)
        {
            // Pending/Testing configurations may only be exercised by an administrator through a test login.
            if (!isTest || user.Role != UserRoles.Admin)
                return await DenyAsync(customerId, "SSO is not active for this organization.");
            await sso.MarkTestSucceededAsync(config);
            await customers.AuditAsync(customerId, "SsoTestSucceeded", user.Email, config.AuthenticationType);
        }

        var identity = new ClaimsIdentity("AppSession", ClaimTypes.Name, ClaimTypes.Role);
        identity.AddClaim(new Claim(ClaimTypes.Name, string.IsNullOrEmpty(user.Email) ? user.Id.ToString() : user.Email));
        identity.AddClaim(new Claim(ClaimTypes.Role, user.Role));
        identity.AddClaim(new Claim(AppClaims.UserId, user.Id.ToString()));
        identity.AddClaim(new Claim(AppClaims.CustomerId, customer.Id.ToString()));
        identity.AddClaim(new Claim(AppClaims.CustomerName, customer.Name));
        identity.AddClaim(new Claim(AppClaims.IdentityProvider, type));
        await customers.AuditAsync(customerId, "SignIn", user.Email, type);
        return new TenantAuthorizationResult(true, new ClaimsPrincipal(identity), null);
    }

    private async Task<TenantAuthorizationResult> DenyAsync(Guid? customerId, string reason)
    {
        await customers.AuditAsync(customerId, "SignInDenied", null, reason);
        return TenantAuthorizationResult.Fail(reason);
    }

    private static string? First(ClaimsPrincipal p, params string[] types) =>
        types.Select(t => p.FindFirst(t)?.Value).FirstOrDefault(v => !string.IsNullOrEmpty(v));
}
