namespace HelloWorldSSO.Models;

public class AuditLog
{
    public long Id { get; set; }

    public Guid? CustomerId { get; set; }

    public string Actor { get; set; } = "";

    public string Action { get; set; } = "";

    public string? Details { get; set; }

    public string? IpAddress { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
