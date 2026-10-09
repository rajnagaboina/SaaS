namespace HelloWorldSSO.Models;

public static class UserRoles
{
    public const string Admin = "Admin";
    public const string User = "User";
}

public class CustomerUser
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CustomerId { get; set; }
    public Customer? Customer { get; set; }
    public string IdentityProvider { get; set; } = AuthenticationTypes.EntraOidc;
    /// <summary>Entra: "{tenantId}:{objectId}". SAML: "{issuer}|{nameId}". Dev: email.</summary>
    public string ExternalUserId { get; set; } = "";
    public string Email { get; set; } = "";
    public string Role { get; set; } = UserRoles.User;
    public string Status { get; set; } = "Active";
}

public class AuditEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid? CustomerId { get; set; }
    public string Action { get; set; } = "";
    public string? Actor { get; set; }
    public string? Detail { get; set; }
    public DateTime At { get; set; } = DateTime.UtcNow;
}
