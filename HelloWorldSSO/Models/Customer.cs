namespace HelloWorldSSO.Models;

public static class CustomerStatus
{
    public const string Active = "Active";
    public const string Suspended = "Suspended";
}

public class Customer
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    /// <summary>Short, URL-safe organization key used on the login page.</summary>
    public string Slug { get; set; } = "";
    public string Status { get; set; } = CustomerStatus.Active;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
