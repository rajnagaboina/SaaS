using HelloWorldSSO.Authentication;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages;

public class LoginModel(CustomerService customers, SsoConfigurationService ssoConfigurations) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Slug { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty]
    public string? Organization { get; set; }

    public Customer? Customer { get; private set; }

    public List<SsoConfiguration> ActiveConfigurations { get; private set; } = [];

    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        if (Slug is null)
            return Page();

        await LoadAsync();
        if (Customer is null)
            Error = "We couldn't find that organization.";
        return Page();
    }

    public IActionResult OnPostFind()
    {
        var slug = Organization?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(slug))
        {
            Error = "Enter your organization's identifier.";
            return Page();
        }
        return RedirectToPage(new { slug, returnUrl = ReturnUrl });
    }

    public async Task<IActionResult> OnPostSignInAsync(Guid configurationId)
    {
        await LoadAsync();
        var config = ActiveConfigurations.FirstOrDefault(c => c.Id == configurationId);
        if (Customer is null || config is null)
            return RedirectToPage(new { slug = Slug });

        return SignInRequests.ForConfiguration(config, AuthFlows.Login, LoginItems());
    }

    /// <summary>Lets an invited administrator sign in with the Microsoft account they were linked to.</summary>
    public async Task<IActionResult> OnPostRecoveryAsync()
    {
        await LoadAsync();
        if (Customer is null)
            return RedirectToPage(new { slug = (string?)null });
        return SignInRequests.Entra(null, AuthFlows.Login, LoginItems());
    }

    public IActionResult OnPostOperator() => SignInRequests.Entra(null, AuthFlows.Operator);

    private Dictionary<string, string?> LoginItems() => new()
    {
        [AuthItems.CustomerId] = Customer!.Id.ToString(),
        [AuthItems.ReturnUrl] = Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/",
    };

    private async Task LoadAsync()
    {
        if (string.IsNullOrWhiteSpace(Slug))
            return;
        Customer = await customers.FindBySlugAsync(Slug);
        if (Customer is { Status: CustomerStatus.Active })
            ActiveConfigurations = await ssoConfigurations.ListActiveAsync(Customer.Id);
        else if (Customer is not null)
        {
            Error = "This organization's access is currently suspended.";
            Customer = null;
        }
    }
}
