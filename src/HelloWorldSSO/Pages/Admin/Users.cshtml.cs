using HelloWorldSSO.Authentication;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages.Admin;

public class UsersModel(CustomerService customers) : PageModel
{
    public Customer Customer { get; private set; } = null!;
    public List<CustomerUser> Users { get; private set; } = [];
    public List<Invitation> Invitations { get; private set; } = [];
    public string? Error { get; private set; }

    [BindProperty] public string? InviteEmail { get; set; }
    [BindProperty] public string InviteRole { get; set; } = UserRoles.User;

    public async Task OnGetAsync() => await LoadAsync();

    public async Task<IActionResult> OnPostInviteAsync()
    {
        var (token, error) = await customers.CreateInvitationAsync(User.GetCustomerId(), InviteEmail ?? "", InviteRole, User.GetEmail() ?? "");
        if (error is not null)
        {
            Error = error;
            await LoadAsync();
            return Page();
        }
        TempData["InviteLink"] = $"{Request.Scheme}://{Request.Host}/invite/{token}";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostSetStatusAsync(Guid userId, string status)
    {
        Error = await customers.SetUserStatusAsync(User.GetCustomerId(), userId, status, User.GetUserId());
        if (Error is null) return RedirectToPage();
        await LoadAsync();
        return Page();
    }

    public async Task<IActionResult> OnPostAutoProvisionAsync(bool enabled)
    {
        await customers.SetAutoProvisionAsync(User.GetCustomerId(), enabled);
        return RedirectToPage();
    }

    private async Task LoadAsync()
    {
        var customerId = User.GetCustomerId();
        Customer = (await customers.GetAsync(customerId))!;
        Users = await customers.ListUsersAsync(customerId);
        Invitations = await customers.ListInvitationsAsync(customerId);
    }
}
