using HelloWorldSSO.Authentication;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages;

public class IndexModel : PageModel
{
    public string CustomerName { get; private set; } = "";
    public string Provider { get; private set; } = "";

    public void OnGet()
    {
        CustomerName = User.FindFirst(AppClaims.CustomerName)?.Value ?? "";
        Provider = User.FindFirst(AppClaims.IdentityProvider)?.Value ?? "";
    }
}
