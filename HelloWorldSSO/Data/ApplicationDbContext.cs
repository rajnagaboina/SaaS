using HelloWorldSSO.Models;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Data;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : DbContext(options)
{
    public DbSet<Customer> Customers => Set<Customer>();
    public DbSet<SsoConfiguration> SsoConfigurations => Set<SsoConfiguration>();
    public DbSet<CustomerUser> CustomerUsers => Set<CustomerUser>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Customer>(e =>
        {
            e.Property(x => x.Name).HasMaxLength(200).IsRequired();
            e.Property(x => x.Slug).HasMaxLength(64).IsRequired();
            e.Property(x => x.Status).HasMaxLength(32);
            e.HasIndex(x => x.Slug).IsUnique();
        });
        // Not unique on CustomerId: a customer may eventually have several IdP configurations.
        b.Entity<SsoConfiguration>(e =>
        {
            e.Property(x => x.AuthenticationType).HasMaxLength(32);
            e.Property(x => x.Status).HasMaxLength(32);
            e.Property(x => x.EntraTenantId).HasMaxLength(64);
            e.Property(x => x.SamlEntityId).HasMaxLength(512);
            e.HasIndex(x => x.CustomerId);
            e.HasOne(x => x.Customer).WithMany().HasForeignKey(x => x.CustomerId);
        });
        b.Entity<CustomerUser>(e =>
        {
            e.Property(x => x.IdentityProvider).HasMaxLength(32);
            e.Property(x => x.ExternalUserId).HasMaxLength(768);
            e.Property(x => x.Email).HasMaxLength(320);
            e.Property(x => x.Role).HasMaxLength(32);
            e.Property(x => x.Status).HasMaxLength(32);
            e.HasIndex(x => new { x.CustomerId, x.IdentityProvider, x.ExternalUserId }).IsUnique();
            e.HasOne(x => x.Customer).WithMany().HasForeignKey(x => x.CustomerId);
        });
        b.Entity<AuditEvent>(e => e.HasIndex(x => x.At));
    }
}
