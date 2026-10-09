using System.Security.Claims;
using HelloWorldSSO.Authentication;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages;

public class LoginModel(CustomerService customers, SsoConfigurationService sso, IHostEnvironment env) : PageModel
{
    [BindProperty] public string? Organization { get; set; }
    public string? Error { get; private set; }
    public bool DevLoginEnabled => env.IsDevelopment();

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        // Same message for every failure so the form does not reveal which organizations exist.
        const string generic = "Single sign-on is not available for that organization.";
        var customer = string.IsNullOrWhiteSpace(Organization) ? null : await customers.GetBySlugAsync(Organization);
        if (customer is null || customer.Status != CustomerStatus.Active) { Error = generic; return Page(); }

        var active = (await sso.ListAsync(customer.Id)).FirstOrDefault(c => c.Status == SsoStatus.Active);
        if (active is null) { Error = generic; return Page(); }

        var (scheme, props) = SsoLoginHelper.BuildChallenge(active, test: false);
        return Challenge(props, scheme);
    }

    public async Task<IActionResult> OnPostDevAsync(string? organization, string? email)
    {
        if (!env.IsDevelopment()) return NotFound();
        var customer = string.IsNullOrWhiteSpace(organization) ? null : await customers.GetBySlugAsync(organization);
        if (customer is null || string.IsNullOrWhiteSpace(email)) { Error = "Unknown organization."; return Page(); }

        var props = new AuthenticationProperties { RedirectUri = "/" };
        props.Items[AppClaims.PropType] = AuthenticationTypes.Dev;
        props.Items[AppClaims.PropCustomer] = customer.Id.ToString();
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Email, email)], "Dev"));
        await HttpContext.SignInAsync(SessionAuthentication.CookieScheme, principal, props);
        return LocalRedirect(props.RedirectUri ?? "/");
    }
}
