using HelloWorldSSO.Authentication;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages.Admin.Sso;

/// <summary>Test / activate / disable actions shared by the Entra and SAML configuration screens.</summary>
public abstract class SsoConfigurationPageModel(SsoConfigurationService ssoConfigurations, string authenticationType) : PageModel
{
    protected SsoConfigurationService SsoConfigurations => ssoConfigurations;

    [BindProperty(SupportsGet = true)]
    public Guid Id { get; set; }

    public SsoConfiguration Config { get; private set; } = null!;

    public SsoOperationResult? Result { get; protected set; }

    public bool IsEditable => Config.Status is SsoStatus.Pending or SsoStatus.Testing;

    protected async Task<bool> LoadAsync()
    {
        var config = await ssoConfigurations.GetAsync(User.GetCustomerId(), Id);
        if (config is null || config.AuthenticationType != authenticationType)
            return false;
        Config = config;
        return true;
    }

    public async Task<IActionResult> OnGetAsync() => await LoadAsync() ? Page() : NotFound();

    public async Task<IActionResult> OnPostTestAsync()
    {
        if (!await LoadAsync()) return NotFound();
        if (Config.Status is not (SsoStatus.Testing or SsoStatus.Active))
        {
            Result = SsoOperationResult.Fail("Save a valid configuration before testing.");
            return Page();
        }

        // The test signs in through the customer's IdP but never replaces the admin's session.
        return SignInRequests.ForConfiguration(Config, AuthFlows.Test, new Dictionary<string, string?>
        {
            [AuthItems.CustomerId] = User.GetCustomerId().ToString(),
            [AuthItems.InitiatorUserId] = User.GetUserId().ToString(),
        });
    }

    public async Task<IActionResult> OnPostActivateAsync()
    {
        var result = await ssoConfigurations.ActivateAsync(User.GetCustomerId(), Id);
        return await AfterActionAsync(result, "SSO activated. Users can now sign in with this configuration.");
    }

    public async Task<IActionResult> OnPostDisableAsync()
    {
        var result = await ssoConfigurations.DisableAsync(User.GetCustomerId(), Id);
        return await AfterActionAsync(result, "Configuration disabled.");
    }

    protected async Task<IActionResult> AfterActionAsync(SsoOperationResult result, string successMessage)
    {
        if (result.Succeeded)
        {
            TempData["Message"] = successMessage;
            if (result.Warnings.Count > 0)
                TempData["Warning"] = string.Join(" ", result.Warnings);
            return RedirectToPage(new { id = Id });
        }
        Result = result;
        return await LoadAsync() ? Page() : NotFound();
    }
}
