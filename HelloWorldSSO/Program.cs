using HelloWorldSSO.Authentication;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages(o =>
{
    o.Conventions.AuthorizeFolder("/Admin", Policies.TenantAdmin);
    foreach (var page in new[] { "/Login", "/Logout", "/AccessDenied", "/Error", "/Privacy" })
        o.Conventions.AllowAnonymousToPage(page);
});

var connection = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(o =>
{
    if (string.IsNullOrWhiteSpace(connection)) o.UseInMemoryDatabase("HelloWorldSSO");
    else o.UseSqlServer(connection);
});

builder.Services.AddScoped<CustomerService>();
builder.Services.AddScoped<SsoConfigurationService>();
builder.Services.AddScoped<TenantAuthorizationService>();

builder.Services.AddHttpClient(SafeMetadataFetcher.ClientName)
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(5),
        ConnectCallback = SafeMetadataFetcher.ConnectAsync,
    })
    .ConfigureHttpClient(c => c.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddScoped<SafeMetadataFetcher>();

builder.Services.AddAuthentication(SessionAuthentication.CookieScheme)
    .AddEntra(builder.Configuration)
    .AddSaml(builder.Configuration);
builder.Services.Configure<CookieAuthenticationOptions>(SessionAuthentication.CookieScheme, SessionAuthentication.Configure);
builder.Services.AddAuthorization(SessionAuthentication.AddPolicies);

var app = builder.Build();
ServiceProviderAccessor.Root = app.Services;

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
else
{
    await DevSeed.RunAsync(app.Services, app.Configuration);
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages().WithStaticAssets();

app.Run();

public partial class Program;
