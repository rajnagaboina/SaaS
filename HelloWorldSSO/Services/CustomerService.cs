using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Services;

public class CustomerService(ApplicationDbContext db)
{
    public Task<Customer?> GetAsync(Guid id) => db.Customers.FirstOrDefaultAsync(c => c.Id == id);

    public Task<Customer?> GetBySlugAsync(string slug)
    {
        slug = slug.Trim().ToLowerInvariant();
        return db.Customers.FirstOrDefaultAsync(c => c.Slug == slug);
    }

    public async Task<Customer> CreateAsync(string name, string slug)
    {
        var c = new Customer { Name = name.Trim(), Slug = slug.Trim().ToLowerInvariant() };
        db.Customers.Add(c);
        await db.SaveChangesAsync();
        return c;
    }

    /// <summary>Invites a user; the external identity is linked on first successful sign-in.</summary>
    public async Task<CustomerUser> InviteUserAsync(Guid customerId, string email, string role, string idp)
    {
        var u = new CustomerUser { CustomerId = customerId, Email = email.Trim(), Role = role, IdentityProvider = idp, ExternalUserId = "" };
        db.CustomerUsers.Add(u);
        await db.SaveChangesAsync();
        return u;
    }

    public async Task AuditAsync(Guid? customerId, string action, string? actor, string? detail = null)
    {
        db.AuditEvents.Add(new AuditEvent { CustomerId = customerId, Action = action, Actor = actor, Detail = detail });
        await db.SaveChangesAsync();
    }
}
