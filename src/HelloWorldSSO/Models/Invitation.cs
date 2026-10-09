namespace HelloWorldSSO.Models;

/// <summary>
/// A single-use invitation that links a newly authenticated identity to a customer with a
/// specific role. This is the only way to become a customer administrator.
/// </summary>
public class Invitation
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid CustomerId { get; set; }

    public Customer? Customer { get; set; }

    public string Email { get; set; } = "";

    public string Role { get; set; } = UserRoles.User;

    /// <summary>SHA-256 of the token; the token itself is only shown once, to the inviter.</summary>
    public string TokenHash { get; set; } = "";

    public DateTime ExpiresAt { get; set; }

    public DateTime? RedeemedAt { get; set; }

    public Guid? RedeemedByUserId { get; set; }

    public string CreatedBy { get; set; } = "";

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
