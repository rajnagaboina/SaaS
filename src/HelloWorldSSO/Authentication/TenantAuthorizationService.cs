using System.Security.Claims;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Authentication;

public record AuthorizationOutcome(bool Succeeded, ClaimsPrincipal? Principal, string RedirectUrl, string? Error)
{
    public static AuthorizationOutcome Deny(string error) => new(false, null, "/access-denied", error);
}

/// <summary>
/// The single gate every external sign-in passes through, whichever protocol was used. It
/// confirms the identity provider matches what the customer configured, the customer and
/// user are active, and only then builds the application session principal.
/// </summary>
public class TenantAuthorizationService(
    ApplicationDbContext db,
    AuditService audit,
    CustomerService customers,
    IConfiguration configuration,
    ILogger<TenantAuthorizationService> logger)
{
    public async Task<AuthorizationOutcome> AuthorizeAsync(ClaimsPrincipal externalPrincipal, AuthenticationProperties properties, ClaimsPrincipal currentUser)
    {
        var items = properties.Items;
        var flow = Item(items, AuthItems.Flow);
        var scheme = Item(items, AuthItems.Scheme) ?? "";

        // 1. The authentication response was validated by the protocol handler; map it explicitly.
        var identity = ExternalIdentity.FromPrincipal(externalPrincipal, scheme);
        if (identity is null)
        {
            logger.LogWarning("External sign-in via {Scheme} lacked the claims needed to identify the user.", scheme);
            return AuthorizationOutcome.Deny("Your identity provider did not send a usable user identifier.");
        }

        return flow switch
        {
            AuthFlows.Login => await LoginAsync(identity, items),
            AuthFlows.Test => await TestAsync(identity, items, currentUser),
            AuthFlows.Invite => await InviteAsync(identity, items),
            AuthFlows.Operator => await OperatorAsync(identity),
            _ => AuthorizationOutcome.Deny("Unrecognized sign-in request."),
        };
    }

    private async Task<AuthorizationOutcome> LoginAsync(ExternalIdentity identity, IDictionary<string, string?> items)
    {
        if (!Guid.TryParse(Item(items, AuthItems.CustomerId), out var customerId))
            return AuthorizationOutcome.Deny("Missing organization.");

        // 3. The customer is active.
        var customer = await db.Customers.FirstOrDefaultAsync(c => c.Id == customerId);
        if (customer is null || customer.Status != CustomerStatus.Active)
            return await DenyAsync(customerId, identity, "Organization is not active.");

        var user = await db.CustomerUsers.FirstOrDefaultAsync(u =>
            u.CustomerId == customerId && u.IdentityProvider == identity.Provider && u.ExternalUserId == identity.ExternalUserId);

        // 2. The identity provider matches one of the customer's active configurations.
        var activeConfigs = await db.SsoConfigurations
            .Where(c => c.CustomerId == customerId && c.Status == SsoStatus.Active)
            .ToListAsync();
        var matchingConfig = activeConfigs.FirstOrDefault(c => Matches(c, identity));

        if (matchingConfig is null)
        {
            // Recovery path: an invited administrator may always sign in with the identity they
            // were linked to, so a broken SSO configuration cannot lock the organization out.
            if (user is not { Role: UserRoles.Admin, Status: UserStatus.Active })
                return await DenyAsync(customerId, identity, "This identity provider is not enabled for your organization.");
            audit.Record(customerId, "SignIn.AdminRecovery", $"{identity.Provider} {identity.Issuer}", Actor(identity));
        }

        // 4. The user is authorized for this customer.
        if (user is null)
        {
            if (matchingConfig is null || !customer.AutoProvisionUsers)
                return await DenyAsync(customerId, identity, "You have not been granted access to this organization.");

            user = new CustomerUser
            {
                CustomerId = customerId,
                IdentityProvider = identity.Provider,
                ExternalUserId = identity.ExternalUserId,
                Role = UserRoles.User, // never Admin: admins come only from invitations
            };
            db.CustomerUsers.Add(user);
            audit.Record(customerId, "User.AutoProvisioned", identity.Email, Actor(identity));
        }

        if (user.Status != UserStatus.Active)
            return await DenyAsync(customerId, identity, "Your account for this organization is disabled.");

        user.Email = identity.Email;
        user.DisplayName = identity.DisplayName;
        user.LastSignInAt = DateTime.UtcNow;
        audit.Record(customerId, "SignIn.Succeeded", $"{identity.Provider} config={matchingConfig?.Id}", Actor(identity));
        await db.SaveChangesAsync();

        return new AuthorizationOutcome(true, BuildPrincipal(user, customer, identity), LocalReturnUrl(items), null);
    }

    private async Task<AuthorizationOutcome> TestAsync(ExternalIdentity identity, IDictionary<string, string?> items, ClaimsPrincipal currentUser)
    {
        if (!Guid.TryParse(Item(items, AuthItems.CustomerId), out var customerId)
            || !Guid.TryParse(Item(items, AuthItems.ConfigurationId), out var configId))
            return AuthorizationOutcome.Deny("Malformed test request.");

        // The test must complete in the same admin session that started it.
        if (currentUser.FindFirst(AppClaims.UserId)?.Value != Item(items, AuthItems.InitiatorUserId)
            || currentUser.FindFirst(AppClaims.CustomerId)?.Value != customerId.ToString()
            || !currentUser.IsInRole(UserRoles.Admin))
            return AuthorizationOutcome.Deny("The test sign-in must be completed by the administrator who started it.");

        var config = await db.SsoConfigurations.FirstOrDefaultAsync(c => c.Id == configId && c.CustomerId == customerId);
        if (config is null || config.Status is not (SsoStatus.Testing or SsoStatus.Active))
            return AuthorizationOutcome.Deny("Configuration is not ready for testing.");

        var success = Matches(config, identity);
        config.LastTestedAt = DateTime.UtcNow;
        config.LastTestSucceeded = success;
        config.LastTestMessage = success
            ? $"Signed in as {identity.DisplayName} <{identity.Email}> (ID {identity.ExternalUserId})."
            : $"Sign-in succeeded but came from {identity.Issuer}, which does not match this configuration.";
        audit.Record(customerId, success ? "Sso.TestSucceeded" : "Sso.TestFailed", $"config={configId} {config.LastTestMessage}");
        await db.SaveChangesAsync();

        // The test never changes who is signed in to the application.
        var page = config.AuthenticationType == AuthenticationTypes.Saml ? "Saml" : "Entra";
        return new AuthorizationOutcome(true, null, $"/admin/sso/{page}/{configId}", null);
    }

    private async Task<AuthorizationOutcome> InviteAsync(ExternalIdentity identity, IDictionary<string, string?> items)
    {
        var token = Item(items, AuthItems.InvitationToken);
        var invitation = token is null ? null : await customers.FindRedeemableInvitationAsync(token);
        if (invitation is null)
            return AuthorizationOutcome.Deny("This invitation is invalid, expired, or has already been used.");

        var customer = await db.Customers.FirstAsync(c => c.Id == invitation.CustomerId);
        if (customer.Status != CustomerStatus.Active)
            return await DenyAsync(customer.Id, identity, "Organization is not active.");

        if (!string.Equals(identity.Email, invitation.Email, StringComparison.OrdinalIgnoreCase))
            return await DenyAsync(customer.Id, identity,
                $"This invitation was sent to {invitation.Email}, but you signed in as {(identity.Email.Length > 0 ? identity.Email : "an account without an email address")}.");

        // SAML invitations may only be redeemed through one of the customer's own active IdPs.
        if (identity.Provider == AuthenticationTypes.Saml)
        {
            var allowed = await db.SsoConfigurations.AnyAsync(c => c.CustomerId == customer.Id && c.Status == SsoStatus.Active
                && c.AuthenticationType == AuthenticationTypes.Saml && c.SamlEntityId == identity.Issuer);
            if (!allowed)
                return await DenyAsync(customer.Id, identity, "This SAML identity provider is not active for the organization.");
        }

        var user = await customers.RedeemInvitationAsync(invitation, identity);
        return new AuthorizationOutcome(true, BuildPrincipal(user, customer, identity),
            user.Role == UserRoles.Admin ? "/admin/sso" : "/", null);
    }

    private async Task<AuthorizationOutcome> OperatorAsync(ExternalIdentity identity)
    {
        var operators = configuration.GetSection("Platform:Operators").Get<string[]>() ?? [];
        if (identity.Provider != AuthenticationTypes.EntraOidc
            || !operators.Any(o => string.Equals(o.Trim(), identity.ExternalUserId, StringComparison.OrdinalIgnoreCase)))
        {
            await audit.RecordNowAsync(null, "Operator.SignInDenied", identity.ExternalUserId, Actor(identity));
            return AuthorizationOutcome.Deny(
                $"This account is not a platform operator. To make it one, add \"{identity.ExternalUserId}\" to Platform:Operators.");
        }

        await audit.RecordNowAsync(null, "Operator.SignIn", null, Actor(identity));
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, identity.DisplayName),
            new(AppClaims.Email, identity.Email),
            new(AppClaims.ExternalId, identity.ExternalUserId),
            new(AppClaims.IdentityProvider, identity.Provider),
            new(ClaimTypes.Role, UserRoles.PlatformAdmin),
            new(AppClaims.ValidatedAt, DateTime.UtcNow.ToString("O")),
        };
        return new AuthorizationOutcome(true, new ClaimsPrincipal(new ClaimsIdentity(claims, AuthSchemes.App)), "/platform", null);
    }

    /// <summary>The identity came from exactly the provider this configuration describes.</summary>
    public static bool Matches(SsoConfiguration config, ExternalIdentity identity) => config.AuthenticationType switch
    {
        AuthenticationTypes.EntraOidc => identity.Provider == AuthenticationTypes.EntraOidc
                                         && string.Equals(config.EntraTenantId, identity.Issuer, StringComparison.OrdinalIgnoreCase),
        AuthenticationTypes.Saml => identity.Provider == AuthenticationTypes.Saml
                                    && string.Equals(config.SamlEntityId, identity.Issuer, StringComparison.Ordinal),
        _ => false,
    };

    public static ClaimsPrincipal BuildPrincipal(CustomerUser user, Customer customer, ExternalIdentity identity)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.DisplayName.Length > 0 ? user.DisplayName : user.Email),
            new(AppClaims.Email, user.Email),
            new(AppClaims.UserId, user.Id.ToString()),
            new(AppClaims.CustomerId, customer.Id.ToString()),
            new(AppClaims.CustomerName, customer.Name),
            new(AppClaims.IdentityProvider, identity.Provider),
            new(AppClaims.ExternalId, identity.ExternalUserId),
            new(ClaimTypes.Role, user.Role),
            new(AppClaims.ValidatedAt, DateTime.UtcNow.ToString("O")),
        };
        return new ClaimsPrincipal(new ClaimsIdentity(claims, AuthSchemes.App));
    }

    private async Task<AuthorizationOutcome> DenyAsync(Guid customerId, ExternalIdentity identity, string reason)
    {
        await audit.RecordNowAsync(customerId, "SignIn.Denied", reason, Actor(identity));
        return AuthorizationOutcome.Deny(reason);
    }

    private static string? Item(IDictionary<string, string?> items, string key) => items.TryGetValue(key, out var value) ? value : null;

    private static string Actor(ExternalIdentity identity) => $"{identity.Email} ({identity.ExternalUserId})";

    private static string LocalReturnUrl(IDictionary<string, string?> items)
    {
        var url = Item(items, AuthItems.ReturnUrl);
        return url is { Length: > 0 } && url.StartsWith('/') && !url.StartsWith("//") && !url.StartsWith("/\\") ? url : "/";
    }
}
