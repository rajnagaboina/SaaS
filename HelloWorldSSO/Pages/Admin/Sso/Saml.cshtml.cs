using HelloWorldSSO.Authentication;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages.Admin.Sso;

public class SamlModel(SsoConfigurationService sso, CustomerService customers) : PageModel
{
    [BindProperty] public string? MetadataUrl { get; set; }
    public string? Error { get; private set; }
    public string BaseUrl => $"{Request.Scheme}://{Request.Host}";

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(IFormFile? metadataFile)
    {
        var customerId = Guid.Parse(User.FindFirst(AppClaims.CustomerId)!.Value);
        try
        {
            string? xml = null;
            if (metadataFile is { Length: > 0 })
            {
                if (metadataFile.Length > SamlMetadataParser.MaxMetadataBytes)
                    throw new SamlMetadataException("Metadata is too large.");
                using var reader = new StreamReader(metadataFile.OpenReadStream());
                xml = await reader.ReadToEndAsync();
            }
            var cfg = await sso.SaveSamlAsync(customerId, xml, MetadataUrl);
            await customers.AuditAsync(customerId, "SamlConfigured", User.Identity?.Name, cfg.SamlEntityId);
            return RedirectToPage("Index");
        }
        catch (Exception ex) when (ex is SsoConfigurationException or SamlMetadataException)
        {
            Error = ex.Message;
            return Page();
        }
    }
}
