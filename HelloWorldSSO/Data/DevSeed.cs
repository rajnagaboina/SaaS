using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Data;

/// <summary>Development-only bootstrap: one customer and a pre-provisioned administrator.</summary>
public static class DevSeed
{
    public static async Task RunAsync(IServiceProvider services, IConfiguration config)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await db.Database.EnsureCreatedAsync();
        if (await db.Customers.AnyAsync()) return;
        var customers = scope.ServiceProvider.GetRequiredService<CustomerService>();
        var c = await customers.CreateAsync("Contoso", "contoso");
        await customers.InviteUserAsync(c.Id, config["Seed:AdminEmail"] ?? "admin@contoso.test", UserRoles.Admin, AuthenticationTypes.EntraOidc);
    }
}
