namespace HelloWorldSSO.Models;

public static class AuthenticationTypes
{
    public const string EntraOidc = "EntraOIDC";
    public const string Saml = "SAML";
    public const string Dev = "Dev";
    public static readonly string[] Supported = [EntraOidc, Saml];
}

public static class SsoStatus
{
    public const string Pending = "Pending";
    public const string Testing = "Testing";
    public const string Active = "Active";
    public const string Disabled = "Disabled";
}

public class SsoConfiguration
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CustomerId { get; set; }
    public Customer? Customer { get; set; }
    public string AuthenticationType { get; set; } = AuthenticationTypes.EntraOidc;
    public string? EntraTenantId { get; set; }
    public string? SamlEntityId { get; set; }
    public string? SamlSingleSignOnUrl { get; set; }
    /// <summary>Normalized signing certificates (base64 DER), separated by newlines.</summary>
    public string? SamlSigningCertificates { get; set; }
    /// <summary>The reviewed IdP metadata XML this configuration was derived from.</summary>
    public string? SamlMetadata { get; set; }
    public string Status { get; set; } = SsoStatus.Pending;
    public DateTime? LastTestSucceededAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
