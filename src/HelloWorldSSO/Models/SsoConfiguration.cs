namespace HelloWorldSSO.Models;

public class SsoConfiguration
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid CustomerId { get; set; }

    public Customer? Customer { get; set; }

    /// <summary><see cref="AuthenticationTypes.EntraOidc"/> or <see cref="AuthenticationTypes.Saml"/>.</summary>
    public string AuthenticationType { get; set; } = "";

    public string? EntraTenantId { get; set; }

    // --- SAML: normalized values extracted from validated IdP metadata ---

    public string? SamlEntityId { get; set; }

    /// <summary>Raw validated IdP metadata XML, kept for review and re-validation.</summary>
    public string? SamlMetadata { get; set; }

    /// <summary>Where the metadata was fetched from, if it was imported by URL.</summary>
    public string? SamlMetadataUrl { get; set; }

    public string? SamlSsoUrl { get; set; }

    /// <summary>"HttpRedirect" or "HttpPost".</summary>
    public string? SamlSsoBinding { get; set; }

    /// <summary>Base64 DER signing certificates, one per line.</summary>
    public string? SamlSigningCertificates { get; set; }

    // --- Lifecycle ---

    public string Status { get; set; } = SsoStatus.Pending;

    public DateTime? LastTestedAt { get; set; }

    public bool LastTestSucceeded { get; set; }

    public string? LastTestMessage { get; set; }

    public DateTime? ActivatedAt { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>A configuration may be activated only after a successful test of its current settings.</summary>
    public bool CanActivate =>
        Status == SsoStatus.Testing && LastTestSucceeded && LastTestedAt >= UpdatedAt;
}

public static class AuthenticationTypes
{
    public const string EntraOidc = "EntraOIDC";
    public const string Saml = "SAML";

    public static bool IsValid(string? value) => value is EntraOidc or Saml;
}

public static class SsoStatus
{
    /// <summary>Configuration started but not yet valid.</summary>
    public const string Pending = "Pending";

    /// <summary>Configuration validated; a test sign-in is allowed.</summary>
    public const string Testing = "Testing";

    /// <summary>Approved for user sign-in.</summary>
    public const string Active = "Active";

    public const string Disabled = "Disabled";
}
