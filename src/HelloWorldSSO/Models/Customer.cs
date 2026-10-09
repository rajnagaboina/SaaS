namespace HelloWorldSSO.Models;

public class Customer
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Name { get; set; } = "";

    /// <summary>Short, URL-safe organization identifier used on the login page (e.g. "contoso").</summary>
    public string Slug { get; set; } = "";

    public string Status { get; set; } = CustomerStatus.Active;

    /// <summary>
    /// When true, a user who authenticates through one of the customer's active SSO
    /// configurations is provisioned automatically with the User role. Admins are never
    /// auto-provisioned; they must come through an invitation.
    /// </summary>
    public bool AutoProvisionUsers { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public List<SsoConfiguration> SsoConfigurations { get; set; } = [];

    public List<CustomerUser> Users { get; set; } = [];
}

public static class CustomerStatus
{
    public const string Active = "Active";
    public const string Suspended = "Suspended";
}
