using HelloWorldSSO.Authentication;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Pages.Platform;

public class CustomerModel(CustomerService customers, SsoConfigurationService ssoConfigurations, ApplicationDbContext db) : PageModel
{
    [BindProperty(SupportsGet = true)] public Guid Id { get; set; }

    public Customer Customer { get; private set; } = null!;
    public List<SsoConfiguration> Configurations { get; private set; } = [];
    public List<CustomerUser> Users { get; private set; } = [];
    public List<AuditLog> AuditLogs { get; private set; } = [];
    public string? Error { get; private set; }

    [BindProperty] public string? AdminEmail { get; set; }

    public async Task<IActionResult> OnGetAsync() => await LoadAsync() ? Page() : NotFound();

    public async Task<IActionResult> OnPostInviteAdminAsync()
    {
        if (!await LoadAsync()) return NotFound();
        var (token, error) = await customers.CreateInvitationAsync(Id, AdminEmail ?? "", UserRoles.Admin, User.GetEmail() ?? "operator");
        if (error is not null)
        {
            Error = error;
            return Page();
        }
        TempData["InviteLink"] = $"{Request.Scheme}://{Request.Host}/invite/{token}";
        return RedirectToPage(new { id = Id });
    }

    public async Task<IActionResult> OnPostSetStatusAsync(string status)
    {
        if (!await LoadAsync()) return NotFound();
        await customers.SetStatusAsync(Id, status);
        return RedirectToPage(new { id = Id });
    }

    private async Task<bool> LoadAsync()
    {
        var customer = await customers.GetAsync(Id);
        if (customer is null) return false;
        Customer = customer;
        Configurations = await ssoConfigurations.ListAsync(Id);
        Users = await customers.ListUsersAsync(Id);
        AuditLogs = await db.AuditLogs.AsNoTracking().Where(a => a.CustomerId == Id)
            .OrderByDescending(a => a.Id).Take(50).ToListAsync();
        return true;
    }
}
