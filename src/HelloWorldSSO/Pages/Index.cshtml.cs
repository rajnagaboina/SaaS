using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages;

/// <summary>Protected by the application's fallback policy: only reachable with an app session.</summary>
public class IndexModel : PageModel
{
    public IActionResult OnGet() =>
        User.IsInRole(Models.UserRoles.PlatformAdmin) ? RedirectToPage("/Platform/Index") : Page();
}
