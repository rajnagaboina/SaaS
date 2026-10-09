namespace HelloWorldSSO.Models;

public class CustomerUser
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid CustomerId { get; set; }

    public Customer? Customer { get; set; }

    /// <summary><see cref="AuthenticationTypes.EntraOidc"/> or <see cref="AuthenticationTypes.Saml"/>.</summary>
    public string IdentityProvider { get; set; } = "";

    /// <summary>
    /// Stable, provider-specific identifier. Entra: "{tenantId}:{objectId}".
    /// SAML: "{issuer}|{nameId}". Never the email address.
    /// </summary>
    public string ExternalUserId { get; set; } = "";

    public string Email { get; set; } = "";

    public string DisplayName { get; set; } = "";

    public string Role { get; set; } = UserRoles.User;

    public string Status { get; set; } = UserStatus.Active;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? LastSignInAt { get; set; }
}

public static class UserRoles
{
    public const string Admin = "Admin";
    public const string User = "User";

    /// <summary>Your own SaaS operators; never stored on a CustomerUser.</summary>
    public const string PlatformAdmin = "PlatformAdmin";

    public static bool IsCustomerRole(string? value) => value is Admin or User;
}

public static class UserStatus
{
    public const string Active = "Active";
    public const string Disabled = "Disabled";
}
