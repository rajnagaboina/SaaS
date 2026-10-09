using HelloWorldSSO.Authentication;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages.Admin.Sso;

public class IndexModel(SsoConfigurationService ssoConfigurations, IConfiguration configuration) : PageModel
{
    public List<SsoConfiguration> Configurations { get; private set; } = [];

    /// <summary>Controlled by Sso:SupportedMethods so the product decides which protocols are offered.</summary>
    public string[] SupportedMethods { get; private set; } = [];

    [BindProperty]
    public string? AuthenticationType { get; set; }

    public async Task OnGetAsync() => await LoadAsync();

    public async Task<IActionResult> OnPostAsync()
    {
        await LoadAsync();
        if (AuthenticationType is null || !SupportedMethods.Contains(AuthenticationType))
        {
            ModelState.AddModelError(nameof(AuthenticationType), "Choose an authentication provider.");
            return Page();
        }

        var config = await ssoConfigurations.CreateAsync(User.GetCustomerId(), AuthenticationType);
        return RedirectToPage(AuthenticationType == AuthenticationTypes.Saml ? "Saml" : "Entra", new { id = config.Id });
    }

    private async Task LoadAsync()
    {
        Configurations = await ssoConfigurations.ListAsync(User.GetCustomerId());
        SupportedMethods = (configuration.GetSection("Sso:SupportedMethods").Get<string[]>()
                            ?? [AuthenticationTypes.EntraOidc, AuthenticationTypes.Saml])
            .Where(AuthenticationTypes.IsValid).ToArray();
    }
}
