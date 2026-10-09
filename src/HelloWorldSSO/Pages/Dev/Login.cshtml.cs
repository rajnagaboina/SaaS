using System.Security.Claims;
using HelloWorldSSO.Authentication;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Pages.Dev;

/// <summary>
/// Local-development shortcut that signs in as a seeded user without an identity provider,
/// so the portal can be exercised before Entra or SAML is set up. Returns 404 unless the app
/// runs in the Development environment with Dev:EnableDevLogin=true.
/// </summary>
public class LoginModel(ApplicationDbContext db, IWebHostEnvironment environment, IConfiguration configuration) : PageModel
{
    public List<CustomerUser> Users { get; private set; } = [];

    private bool Enabled => environment.IsDevelopment() && configuration.GetValue<bool>("Dev:EnableDevLogin");

    public async Task<IActionResult> OnGetAsync()
    {
        if (!Enabled) return NotFound();
        Users = await db.CustomerUsers.Include(u => u.Customer).OrderBy(u => u.Customer!.Name).ThenBy(u => u.Email).ToListAsync();
        return Page();
    }

    public async Task<IActionResult> OnPostUserAsync(Guid userId)
    {
        if (!Enabled) return NotFound();
        var user = await db.CustomerUsers.Include(u => u.Customer).FirstAsync(u => u.Id == userId);
        var identity = new ExternalIdentity(user.IdentityProvider, "dev", user.ExternalUserId, user.Email, user.DisplayName);
        await HttpContext.SignInAsync(AuthSchemes.App, TenantAuthorizationService.BuildPrincipal(user, user.Customer!, identity));
        return Redirect(user.Role == UserRoles.Admin ? "/admin/sso" : "/");
    }

    public async Task<IActionResult> OnPostOperatorAsync()
    {
        if (!Enabled) return NotFound();
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, "Dev Operator"),
            new(AppClaims.Email, "operator@localhost"),
            new(AppClaims.ExternalId, "dev-operator"),
            new(ClaimTypes.Role, UserRoles.PlatformAdmin),
            new(AppClaims.ValidatedAt, DateTime.MaxValue.ToString("O")),
        };
        await HttpContext.SignInAsync(AuthSchemes.App, new ClaimsPrincipal(new ClaimsIdentity(claims, AuthSchemes.App)));
        return Redirect("/platform");
    }
}
