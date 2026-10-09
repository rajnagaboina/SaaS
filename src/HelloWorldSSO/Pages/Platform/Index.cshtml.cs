using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HelloWorldSSO.Pages.Platform;

/// <summary>Your own operators' portal: onboarding steps 1 and 2 (create customer, invite its admin).</summary>
public class IndexModel(CustomerService customers) : PageModel
{
    public List<Customer> Customers { get; private set; } = [];
    public string? Error { get; private set; }

    [BindProperty] public string? Name { get; set; }
    [BindProperty] public string? Slug { get; set; }

    public async Task OnGetAsync() => Customers = await customers.ListAsync();

    public async Task<IActionResult> OnPostCreateAsync()
    {
        var (customer, error) = await customers.CreateAsync(Name ?? "", Slug ?? "");
        if (error is not null)
        {
            Error = error;
            Customers = await customers.ListAsync();
            return Page();
        }
        return RedirectToPage("Customer", new { id = customer!.Id });
    }
}
