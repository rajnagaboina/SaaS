using HelloWorldSSO.Authentication;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages.Admin.Sso;

public class IndexModel(SsoConfigurationService sso, CustomerService customers) : PageModel
{
    public string CustomerName => User.FindFirst(AppClaims.CustomerName)?.Value ?? "";
    public List<SsoConfiguration> Configurations { get; private set; } = [];
    [TempData] public string? Message { get; set; }

    // Always scoped to the signed-in administrator's own customer.
    private Guid CustomerId => Guid.Parse(User.FindFirst(AppClaims.CustomerId)!.Value);

    public async Task OnGetAsync() => Configurations = await sso.ListAsync(CustomerId);

    public IActionResult OnGetContinue(string? provider) => provider switch
    {
        AuthenticationTypes.EntraOidc => RedirectToPage("Entra"),
        AuthenticationTypes.Saml => RedirectToPage("Saml"),
        _ => RedirectToPage(),
    };

    public async Task<IActionResult> OnPostTestAsync(Guid id)
    {
        var cfg = await sso.GetAsync(CustomerId, id);
        if (cfg is null || cfg.Status is not (SsoStatus.Pending or SsoStatus.Testing)) return RedirectToPage();
        var (scheme, props) = SsoLoginHelper.BuildChallenge(cfg, test: true);
        return Challenge(props, scheme);
    }

    public Task<IActionResult> OnPostActivateAsync(Guid id) => Change(id, "SsoActivated", "SSO activated.", sso.ActivateAsync);
    public Task<IActionResult> OnPostDisableAsync(Guid id) => Change(id, "SsoDisabled", "SSO disabled.", sso.DisableAsync);

    private async Task<IActionResult> Change(Guid id, string audit, string success, Func<Guid, Guid, Task> action)
    {
        try
        {
            await action(CustomerId, id);
            await customers.AuditAsync(CustomerId, audit, User.Identity?.Name, id.ToString());
            Message = success;
        }
        catch (SsoConfigurationException ex) { Message = ex.Message; }
        return RedirectToPage();
    }
}
