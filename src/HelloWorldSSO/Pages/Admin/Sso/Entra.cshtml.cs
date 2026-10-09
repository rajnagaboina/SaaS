using HelloWorldSSO.Authentication;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;

namespace HelloWorldSSO.Pages.Admin.Sso;

public class EntraModel(SsoConfigurationService ssoConfigurations, IConfiguration configuration)
    : SsoConfigurationPageModel(ssoConfigurations, AuthenticationTypes.EntraOidc)
{
    [BindProperty]
    public string? TenantId { get; set; }

    public string RedirectUri => EntraAuthentication.RedirectUri(configuration);

    public string? AdminConsentUrl => Config.EntraTenantId is { } tenant
        ? EntraAuthentication.AdminConsentUrl(configuration, tenant, Config.Id.ToString())
        : null;

    public async Task<IActionResult> OnPostSaveAsync()
    {
        var result = await SsoConfigurations.SaveEntraAsync(User.GetCustomerId(), Id, TenantId);
        return await AfterActionAsync(result, "Configuration saved. Run a test sign-in next.");
    }
}
