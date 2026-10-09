using HelloWorldSSO.Authentication;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages;

public class InviteModel(CustomerService customers, SsoConfigurationService ssoConfigurations) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    public Invitation? Invitation { get; private set; }

    public List<SsoConfiguration> SamlConfigurations { get; private set; } = [];

    public async Task OnGetAsync() => await LoadAsync();

    public async Task<IActionResult> OnPostAsync(Guid? samlConfigurationId)
    {
        await LoadAsync();
        if (Invitation is null)
            return Page();

        var items = new Dictionary<string, string?> { [AuthItems.InvitationToken] = Token };
        if (samlConfigurationId is { } id && SamlConfigurations.FirstOrDefault(c => c.Id == id) is { } saml)
            return SignInRequests.Saml(saml.SamlEntityId!, AuthFlows.Invite, items);

        return SignInRequests.Entra(null, AuthFlows.Invite, items);
    }

    private async Task LoadAsync()
    {
        if (string.IsNullOrEmpty(Token))
            return;
        Invitation = await customers.FindRedeemableInvitationAsync(Token);
        if (Invitation is not null)
            SamlConfigurations = (await ssoConfigurations.ListActiveAsync(Invitation.CustomerId))
                .Where(c => c.AuthenticationType == AuthenticationTypes.Saml).ToList();
    }
}
