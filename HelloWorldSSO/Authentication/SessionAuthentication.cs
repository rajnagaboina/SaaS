using HelloWorldSSO.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

namespace HelloWorldSSO.Authentication;

public static class SessionAuthentication
{
    public const string CookieScheme = CookieAuthenticationDefaults.AuthenticationScheme;

    /// <summary>Both OIDC and SAML sign in to this one cookie; OnSigningIn applies the shared tenant authorization.</summary>
    public static void Configure(CookieAuthenticationOptions o)
    {
        o.LoginPath = "/Login";
        o.AccessDeniedPath = "/AccessDenied";
        o.Cookie.HttpOnly = true;
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.ExpireTimeSpan = TimeSpan.FromHours(8);
        o.Events.OnSigningIn = async ctx =>
        {
            var authz = ctx.HttpContext.RequestServices.GetRequiredService<TenantAuthorizationService>();
            var result = await authz.AuthorizeAsync(ctx.Principal!, ctx.Properties);
            if (result.Succeeded)
            {
                ctx.Principal = result.Principal!;
            }
            else
            {
                // Never issue an authenticated session for a denied user.
                ctx.Principal = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity());
                ctx.Properties.RedirectUri = "/AccessDenied";
            }
        };
    }

    public static void AddPolicies(AuthorizationOptions o)
    {
        o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        o.AddPolicy(Policies.TenantAdmin, p => p.RequireAuthenticatedUser().RequireRole(UserRoles.Admin));
    }
}
