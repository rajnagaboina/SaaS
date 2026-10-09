using HelloWorldSSO.Models;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Data;

public static class DatabaseInitializer
{
    public static async Task InitializeAsync(WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var configuration = app.Configuration;

        if (db.Database.IsSqlite())
        {
            // Local development only; SQL Server uses migrations.
            await db.Database.EnsureCreatedAsync();
        }
        else if (configuration.GetValue("Database:MigrateOnStartup", true))
        {
            await db.Database.MigrateAsync();
        }

        if (app.Environment.IsDevelopment() && configuration.GetValue<bool>("Dev:SeedData") && !await db.Customers.AnyAsync())
            await SeedDevelopmentDataAsync(db);
    }

    /// <summary>The two example customers from the design: Contoso (Entra ID) and Fabrikam (SAML).</summary>
    private static async Task SeedDevelopmentDataAsync(ApplicationDbContext db)
    {
        var contoso = new Customer { Name = "Contoso", Slug = "contoso" };
        var fabrikam = new Customer { Name = "Fabrikam", Slug = "fabrikam" };
        db.Customers.AddRange(contoso, fabrikam);

        db.CustomerUsers.AddRange(
            new CustomerUser
            {
                CustomerId = contoso.Id, IdentityProvider = AuthenticationTypes.EntraOidc,
                ExternalUserId = "dev-tenant:contoso-admin", Email = "admin@contoso.example",
                DisplayName = "Contoso Admin", Role = UserRoles.Admin,
            },
            new CustomerUser
            {
                CustomerId = contoso.Id, IdentityProvider = AuthenticationTypes.EntraOidc,
                ExternalUserId = "dev-tenant:contoso-user", Email = "user@contoso.example",
                DisplayName = "Contoso User", Role = UserRoles.User,
            },
            new CustomerUser
            {
                CustomerId = fabrikam.Id, IdentityProvider = AuthenticationTypes.Saml,
                ExternalUserId = "https://idp.fabrikam.example|fabrikam-admin", Email = "admin@fabrikam.example",
                DisplayName = "Fabrikam Admin", Role = UserRoles.Admin,
            });

        await db.SaveChangesAsync();
    }
}
