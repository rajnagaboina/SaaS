using HelloWorldSSO.Authentication;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages.Admin.Sso;

public class EntraModel(SsoConfigurationService sso, CustomerService customers) : PageModel
{
    [BindProperty] public string? TenantId { get; set; }
    public string? Error { get; private set; }
    public string RedirectUri => $"{Request.Scheme}://{Request.Host}/signin-oidc";

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        var customerId = Guid.Parse(User.FindFirst(AppClaims.CustomerId)!.Value);
        try
        {
            var cfg = await sso.SaveEntraAsync(customerId, TenantId ?? "");
            await customers.AuditAsync(customerId, "EntraConfigured", User.Identity?.Name, cfg.EntraTenantId);
            return RedirectToPage("Index");
        }
        catch (SsoConfigurationException ex)
        {
            Error = ex.Message;
            return Page();
        }
    }
}
