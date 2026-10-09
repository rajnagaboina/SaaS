using System.Security.Claims;
using HelloWorldSSO.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages.Auth;

/// <summary>
/// Where every external sign-in lands. Reads the External cookie, runs tenant authorization,
/// and only then issues the application session.
/// </summary>
public class CompleteModel(TenantAuthorizationService tenantAuthorization) : PageModel
{
    public async Task<IActionResult> OnGetAsync()
    {
        var external = await HttpContext.AuthenticateAsync(AuthSchemes.External);
        if (!external.Succeeded || external.Properties is null)
            return RedirectToPage("/Auth/Error", new { reason = "expired" });

        var current = (await HttpContext.AuthenticateAsync(AuthSchemes.App)).Principal ?? new ClaimsPrincipal();
        var outcome = await tenantAuthorization.AuthorizeAsync(external.Principal, external.Properties, current);
        await HttpContext.SignOutAsync(AuthSchemes.External);

        if (!outcome.Succeeded)
        {
            TempData["AuthError"] = outcome.Error;
            return LocalRedirect(outcome.RedirectUrl);
        }

        if (outcome.Principal is not null)
            await HttpContext.SignInAsync(AuthSchemes.App, outcome.Principal);

        return LocalRedirect(outcome.RedirectUrl);
    }
}
