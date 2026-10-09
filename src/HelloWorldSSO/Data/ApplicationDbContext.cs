using HelloWorldSSO.Models;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Data;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : DbContext(options)
{
    public DbSet<Customer> Customers => Set<Customer>();
    public DbSet<SsoConfiguration> SsoConfigurations => Set<SsoConfiguration>();
    public DbSet<CustomerUser> CustomerUsers => Set<CustomerUser>();
    public DbSet<Invitation> Invitations => Set<Invitation>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Customer>(e =>
        {
            e.Property(x => x.Name).HasMaxLength(200);
            e.Property(x => x.Slug).HasMaxLength(64);
            e.Property(x => x.Status).HasMaxLength(32);
            e.HasIndex(x => x.Slug).IsUnique();
        });

        modelBuilder.Entity<SsoConfiguration>(e =>
        {
            e.Property(x => x.AuthenticationType).HasMaxLength(32);
            e.Property(x => x.Status).HasMaxLength(32);
            e.Property(x => x.EntraTenantId).HasMaxLength(64);
            e.Property(x => x.SamlEntityId).HasMaxLength(1024);
            e.Property(x => x.SamlMetadataUrl).HasMaxLength(2048);
            e.Property(x => x.SamlSsoUrl).HasMaxLength(2048);
            e.Property(x => x.SamlSsoBinding).HasMaxLength(32);
            e.Property(x => x.LastTestMessage).HasMaxLength(2000);
            e.HasOne(x => x.Customer).WithMany(c => c.SsoConfigurations).HasForeignKey(x => x.CustomerId);
            // Deliberately not unique per customer: a customer may need several IdP configurations.
            e.HasIndex(x => x.CustomerId);
            e.HasIndex(x => x.EntraTenantId);
            e.HasIndex(x => x.SamlEntityId);
        });

        modelBuilder.Entity<CustomerUser>(e =>
        {
            e.Property(x => x.IdentityProvider).HasMaxLength(32);
            e.Property(x => x.ExternalUserId).HasMaxLength(1500);
            e.Property(x => x.Email).HasMaxLength(320);
            e.Property(x => x.DisplayName).HasMaxLength(200);
            e.Property(x => x.Role).HasMaxLength(32);
            e.Property(x => x.Status).HasMaxLength(32);
            e.HasOne(x => x.Customer).WithMany(c => c.Users).HasForeignKey(x => x.CustomerId);
            e.HasIndex(x => new { x.CustomerId, x.IdentityProvider, x.ExternalUserId }).IsUnique();
        });

        modelBuilder.Entity<Invitation>(e =>
        {
            e.Property(x => x.Email).HasMaxLength(320);
            e.Property(x => x.Role).HasMaxLength(32);
            e.Property(x => x.TokenHash).HasMaxLength(128);
            e.Property(x => x.CreatedBy).HasMaxLength(320);
            e.HasOne(x => x.Customer).WithMany().HasForeignKey(x => x.CustomerId);
            e.HasIndex(x => x.TokenHash).IsUnique();
        });

        modelBuilder.Entity<AuditLog>(e =>
        {
            e.Property(x => x.Actor).HasMaxLength(500);
            e.Property(x => x.Action).HasMaxLength(100);
            e.Property(x => x.Details).HasMaxLength(4000);
            e.Property(x => x.IpAddress).HasMaxLength(64);
            e.HasIndex(x => new { x.CustomerId, x.CreatedAt });
        });
    }
}
