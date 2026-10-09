using HelloWorldSSO.Data;
using HelloWorldSSO.Models;

namespace HelloWorldSSO.Services;

public class AuditService(ApplicationDbContext db, IHttpContextAccessor httpContextAccessor, ILogger<AuditService> logger)
{
    /// <summary>Adds an audit entry to the current unit of work. Caller saves changes.</summary>
    public void Record(Guid? customerId, string action, string? details = null, string? actor = null)
    {
        var http = httpContextAccessor.HttpContext;
        actor ??= http?.User.Identity?.IsAuthenticated == true
            ? $"{http.User.FindFirst(AppClaims.Email)?.Value ?? http.User.Identity.Name} ({http.User.FindFirst(AppClaims.UserId)?.Value ?? http.User.FindFirst(AppClaims.ExternalId)?.Value})"
            : "anonymous";

        db.AuditLogs.Add(new AuditLog
        {
            CustomerId = customerId,
            Actor = Truncate(actor, 500),
            Action = action,
            Details = details is null ? null : Truncate(details, 4000),
            IpAddress = http?.Connection.RemoteIpAddress?.ToString(),
        });

        logger.LogInformation("Audit {Action} customer={CustomerId} actor={Actor} {Details}", action, customerId, actor, details);
    }

    /// <summary>Records and saves immediately; for events outside another unit of work.</summary>
    public async Task RecordNowAsync(Guid? customerId, string action, string? details = null, string? actor = null)
    {
        Record(customerId, action, details, actor);
        await db.SaveChangesAsync();
    }

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];
}
