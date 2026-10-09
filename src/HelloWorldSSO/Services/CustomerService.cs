using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using HelloWorldSSO.Authentication;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Services;

public partial class CustomerService(ApplicationDbContext db, AuditService audit)
{
    public static readonly TimeSpan InvitationLifetime = TimeSpan.FromDays(7);

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")]
    private static partial Regex SlugPattern();

    public Task<List<Customer>> ListAsync() =>
        db.Customers.AsNoTracking().Include(c => c.SsoConfigurations).OrderBy(c => c.Name).ToListAsync();

    public Task<Customer?> GetAsync(Guid id) => db.Customers.FirstOrDefaultAsync(c => c.Id == id);

    public Task<Customer?> FindBySlugAsync(string slug) =>
        db.Customers.AsNoTracking().FirstOrDefaultAsync(c => c.Slug == slug.Trim().ToLower());

    public async Task<(Customer? Customer, string? Error)> CreateAsync(string name, string slug)
    {
        name = name.Trim();
        slug = slug.Trim().ToLowerInvariant();
        if (name.Length is 0 or > 200)
            return (null, "Name is required (max 200 characters).");
        if (!SlugPattern().IsMatch(slug))
            return (null, "Slug must be lowercase letters, digits and hyphens.");
        if (await db.Customers.AnyAsync(c => c.Slug == slug))
            return (null, $"The slug '{slug}' is already taken.");

        var customer = new Customer { Name = name, Slug = slug };
        db.Customers.Add(customer);
        audit.Record(customer.Id, "Customer.Created", $"{name} ({slug})");
        await db.SaveChangesAsync();
        return (customer, null);
    }

    public async Task SetStatusAsync(Guid customerId, string status)
    {
        var customer = await db.Customers.FirstAsync(c => c.Id == customerId);
        customer.Status = status == CustomerStatus.Suspended ? CustomerStatus.Suspended : CustomerStatus.Active;
        audit.Record(customerId, "Customer.StatusChanged", customer.Status);
        await db.SaveChangesAsync();
    }

    public async Task SetAutoProvisionAsync(Guid customerId, bool enabled)
    {
        var customer = await db.Customers.FirstAsync(c => c.Id == customerId);
        customer.AutoProvisionUsers = enabled;
        audit.Record(customerId, "Customer.AutoProvisionChanged", enabled.ToString());
        await db.SaveChangesAsync();
    }

    // ----- Users (always scoped by customer) -----

    public Task<List<CustomerUser>> ListUsersAsync(Guid customerId) =>
        db.CustomerUsers.AsNoTracking().Where(u => u.CustomerId == customerId)
            .OrderBy(u => u.Email).ToListAsync();

    public async Task<string?> SetUserStatusAsync(Guid customerId, Guid userId, string status, Guid actingUserId)
    {
        if (userId == actingUserId)
            return "You cannot change your own account.";
        var user = await db.CustomerUsers.FirstOrDefaultAsync(u => u.Id == userId && u.CustomerId == customerId);
        if (user is null)
            return "User not found.";
        user.Status = status == UserStatus.Disabled ? UserStatus.Disabled : UserStatus.Active;
        audit.Record(customerId, "User.StatusChanged", $"{user.Email} -> {user.Status}");
        await db.SaveChangesAsync();
        return null;
    }

    /// <summary>Re-checked periodically while a session is open, so revocations take effect.</summary>
    public async Task<bool> IsSessionStillValidAsync(Guid customerId, Guid userId, string role)
    {
        return await db.CustomerUsers.AsNoTracking().AnyAsync(u =>
            u.Id == userId && u.CustomerId == customerId && u.Status == UserStatus.Active && u.Role == role
            && u.Customer!.Status == CustomerStatus.Active);
    }

    // ----- Invitations -----

    public Task<List<Invitation>> ListInvitationsAsync(Guid customerId) =>
        db.Invitations.AsNoTracking().Where(i => i.CustomerId == customerId)
            .OrderByDescending(i => i.CreatedAt).Take(50).ToListAsync();

    /// <summary>Creates an invitation and returns the one-time token; only its hash is stored.</summary>
    public async Task<(string? Token, string? Error)> CreateInvitationAsync(Guid customerId, string email, string role, string createdBy)
    {
        email = email.Trim();
        if (!email.Contains('@') || email.Length > 320)
            return (null, "Enter a valid email address.");
        if (!UserRoles.IsCustomerRole(role))
            return (null, "Invalid role.");

        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        db.Invitations.Add(new Invitation
        {
            CustomerId = customerId,
            Email = email,
            Role = role,
            TokenHash = Hash(token),
            ExpiresAt = DateTime.UtcNow.Add(InvitationLifetime),
            CreatedBy = createdBy,
        });
        audit.Record(customerId, "Invitation.Created", $"{email} as {role}");
        await db.SaveChangesAsync();
        return (token, null);
    }

    public Task<Invitation?> FindRedeemableInvitationAsync(string token)
    {
        var hash = Hash(token);
        var now = DateTime.UtcNow;
        return db.Invitations.Include(i => i.Customer)
            .FirstOrDefaultAsync(i => i.TokenHash == hash && i.RedeemedAt == null && i.ExpiresAt > now);
    }

    public async Task<CustomerUser> RedeemInvitationAsync(Invitation invitation, ExternalIdentity identity)
    {
        var user = await db.CustomerUsers.FirstOrDefaultAsync(u => u.CustomerId == invitation.CustomerId
            && u.IdentityProvider == identity.Provider && u.ExternalUserId == identity.ExternalUserId);
        if (user is null)
        {
            user = new CustomerUser
            {
                CustomerId = invitation.CustomerId,
                IdentityProvider = identity.Provider,
                ExternalUserId = identity.ExternalUserId,
            };
            db.CustomerUsers.Add(user);
        }

        // An invitation can grant a role, never downgrade an existing admin.
        if (user.Role != UserRoles.Admin)
            user.Role = invitation.Role;
        user.Status = UserStatus.Active;
        user.Email = identity.Email;
        user.DisplayName = identity.DisplayName;
        user.LastSignInAt = DateTime.UtcNow;

        invitation.RedeemedAt = DateTime.UtcNow;
        invitation.RedeemedByUserId = user.Id;
        audit.Record(invitation.CustomerId, "Invitation.Redeemed", $"{invitation.Email} as {user.Role} via {identity.Provider}",
            $"{identity.Email} ({identity.ExternalUserId})");
        await db.SaveChangesAsync();
        return user;
    }

    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
