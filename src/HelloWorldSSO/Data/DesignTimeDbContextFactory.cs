using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace HelloWorldSSO.Data;

/// <summary>
/// Used by `dotnet ef` so migrations always target SQL Server (the production database),
/// even though local development runs on SQLite with EnsureCreated.
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    public ApplicationDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlServer("Server=(localdb)\\mssqllocaldb;Database=HelloWorldSSO.Design;Trusted_Connection=True")
            .Options;
        return new ApplicationDbContext(options);
    }
}
