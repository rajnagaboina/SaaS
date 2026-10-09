using System.Security.Claims;
using Azure.Identity;
using HelloWorldSSO;
using HelloWorldSSO.Authentication;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Secrets (e.g. connection strings) come from Key Vault in Azure; keys use "--" for ":".
if (builder.Configuration["KeyVault:Uri"] is { Length: > 0 } keyVaultUri)
    builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUri), new DefaultAzureCredential());

// ----- Data -----
var dbProvider = builder.Configuration["Database:Provider"] ?? "SqlServer";
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
        ?? throw new InvalidOperationException("ConnectionStrings:DefaultConnection is not configured.");
    if (dbProvider.Equals("Sqlite", StringComparison.OrdinalIgnoreCase))
        options.UseSqlite(connectionString);
    else
        options.UseSqlServer(connectionString, sql => sql.EnableRetryOnFailure());
});

// ----- Application services -----
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<CustomerService>();
builder.Services.AddScoped<SsoConfigurationService>();
builder.Services.AddScoped<TenantAuthorizationService>();
builder.Services.AddSingleton<SamlMetadataParser>();
builder.Services.AddScoped<SafeMetadataFetcher>();
builder.Services.AddHttpClient(SafeMetadataFetcher.HttpClientName)
    .ConfigurePrimaryHttpMessageHandler(SafeMetadataFetcher.CreateHandler);

// ----- Authentication: app cookie + external cookie + Entra OIDC + SAML -----
var authentication = builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = AuthSchemes.App;
    options.DefaultChallengeScheme = AuthSchemes.App;
});

authentication.AddCookie(AuthSchemes.App, options =>
{
    options.Cookie.Name = "__Host-HelloWorldSSO";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.LoginPath = "/login";
    options.AccessDeniedPath = "/access-denied";
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
    options.Events.OnValidatePrincipal = ValidateSessionAsync;
});

authentication.AddCookie(AuthSchemes.External, options =>
{
    options.Cookie.Name = "__Host-HelloWorldSSO.External";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    // SAML responses arrive as a cross-site POST, so this cookie is set on that request.
    options.Cookie.SameSite = SameSiteMode.None;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(10);
});

authentication.AddSamlAuthentication(builder.Configuration);
authentication.AddEntraAuthentication(builder.Configuration);

builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder(AuthSchemes.App)
        .RequireAuthenticatedUser().Build())
    .AddPolicy(AuthPolicies.CustomerAdmin, p => p.AddAuthenticationSchemes(AuthSchemes.App)
        .RequireRole(UserRoles.Admin).RequireClaim(AppClaims.CustomerId))
    .AddPolicy(AuthPolicies.PlatformAdmin, p => p.AddAuthenticationSchemes(AuthSchemes.App)
        .RequireRole(UserRoles.PlatformAdmin));

builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeFolder("/Admin", AuthPolicies.CustomerAdmin);
    options.Conventions.AuthorizeFolder("/Platform", AuthPolicies.PlatformAdmin);
    options.Conventions.AllowAnonymousToPage("/Login");
    options.Conventions.AllowAnonymousToPage("/Invite");
    options.Conventions.AllowAnonymousToPage("/AccessDenied");
    options.Conventions.AllowAnonymousToPage("/Error");
    options.Conventions.AllowAnonymousToPage("/Privacy");
    options.Conventions.AllowAnonymousToFolder("/Auth");
    options.Conventions.AllowAnonymousToFolder("/Dev");
});

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    // Azure App Service terminates TLS at its front end.
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();

await DatabaseInitializer.InitializeAsync(app);

app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

// Sustainsys reports invalid SAML responses by throwing; show a friendly error instead of a 500.
app.Use(async (context, next) =>
{
    if (!context.Request.Path.StartsWithSegments(SamlAuthentication.ModulePath))
    {
        await next();
        return;
    }
    try
    {
        await next();
    }
    catch (Exception ex) when (ex is not OperationCanceledException && !context.Response.HasStarted)
    {
        // Covers Sustainsys validation errors as well as IdentityModel ones such as replay detection.
        app.Logger.LogWarning(ex, "SAML request to {Path} failed", context.Request.Path);
        context.Response.Redirect("/auth/error?reason=saml");
    }
});

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages().WithStaticAssets();

app.Run();

// Re-validates the session against the database every few minutes so that disabling a user,
// suspending a customer, or changing a role takes effect without waiting for cookie expiry.
static async Task ValidateSessionAsync(CookieValidatePrincipalContext context)
{
    var principal = context.Principal!;
    if (DateTime.TryParse(principal.FindFirst(AppClaims.ValidatedAt)?.Value, null,
            System.Globalization.DateTimeStyles.RoundtripKind, out var validatedAt)
        && DateTime.UtcNow - validatedAt < TimeSpan.FromMinutes(5))
        return;

    bool valid;
    if (principal.IsInRole(UserRoles.PlatformAdmin))
    {
        var operators = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>()
            .GetSection("Platform:Operators").Get<string[]>() ?? [];
        var externalId = principal.FindFirst(AppClaims.ExternalId)?.Value;
        valid = operators.Any(o => string.Equals(o.Trim(), externalId, StringComparison.OrdinalIgnoreCase));
    }
    else
    {
        var customers = context.HttpContext.RequestServices.GetRequiredService<CustomerService>();
        valid = Guid.TryParse(principal.FindFirst(AppClaims.CustomerId)?.Value, out var customerId)
                && Guid.TryParse(principal.FindFirst(AppClaims.UserId)?.Value, out var userId)
                && await customers.IsSessionStillValidAsync(customerId, userId, principal.FindFirst(ClaimTypes.Role)?.Value ?? "");
    }

    if (!valid)
    {
        context.RejectPrincipal();
        await context.HttpContext.SignOutAsync(AuthSchemes.App);
        return;
    }

    var identity = (ClaimsIdentity)principal.Identity!;
    identity.RemoveClaim(identity.FindFirst(AppClaims.ValidatedAt));
    identity.AddClaim(new Claim(AppClaims.ValidatedAt, DateTime.UtcNow.ToString("O")));
    context.ShouldRenew = true;
}
