using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace HelloWorldSSO.Authentication;

public static class EntraAuthentication
{
    public static AuthenticationBuilder AddEntra(this AuthenticationBuilder auth, IConfiguration config)
    {
        // Shared multitenant app registration (TenantId = "organizations"); issuer validation is handled by Microsoft.Identity.Web.
        auth.AddMicrosoftIdentityWebApp(config.GetSection("AzureAd"), OpenIdConnectDefaults.AuthenticationScheme, SessionAuthentication.CookieScheme);

        auth.Services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            var previous = options.Events.OnRedirectToIdentityProvider;
            options.Events.OnRedirectToIdentityProvider = async ctx =>
            {
                // Send the user to the customer's own tenant so only the configured tenant can authenticate.
                if (ctx.Properties.Items.TryGetValue(AppClaims.PropTenant, out var tenant) && Guid.TryParse(tenant, out var tid)
                    && ctx.ProtocolMessage.IssuerAddress is { } address)
                {
                    ctx.ProtocolMessage.IssuerAddress = address.Replace("/organizations/", $"/{tid:D}/", StringComparison.OrdinalIgnoreCase);
                }
                await previous(ctx);
            };
            options.Events.OnRemoteFailure = ctx =>
            {
                ctx.Response.Redirect("/AccessDenied");
                ctx.HandleResponse();
                return Task.CompletedTask;
            };
        });
        return auth;
    }
}
