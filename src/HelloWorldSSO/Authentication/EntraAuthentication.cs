using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace HelloWorldSSO.Authentication;

public static class EntraAuthentication
{
    /// <summary>
    /// Registers Microsoft Entra ID (OIDC) sign-in against the multitenant app registration in
    /// the "AzureAd" configuration section. Microsoft.Identity.Web validates the token and its
    /// tenant-specific issuer; the tenant allowlist is enforced afterwards by
    /// <see cref="TenantAuthorizationService"/>.
    /// </summary>
    public static AuthenticationBuilder AddEntraAuthentication(this AuthenticationBuilder builder, IConfiguration configuration)
    {
        // cookieScheme: null — the OIDC result lands in the External cookie, not the app session.
        builder.AddMicrosoftIdentityWebApp(configuration.GetSection("AzureAd"), AuthSchemes.Oidc, cookieScheme: null);

        builder.Services.PostConfigure<OpenIdConnectOptions>(AuthSchemes.Oidc, options =>
        {
            options.SignInScheme = AuthSchemes.External;
            // Sign-in only: the ID token is all we need, so no client secret is required.
            options.ResponseType = OpenIdConnectResponseType.IdToken;
            options.ResponseMode = OpenIdConnectResponseMode.FormPost;
            options.SaveTokens = false;

            var onRedirect = options.Events.OnRedirectToIdentityProvider;
            options.Events.OnRedirectToIdentityProvider = async context =>
            {
                await onRedirect(context);

                // Send the user to their own tenant's sign-in page when we already know it.
                if (context.Properties.Items.TryGetValue(AuthItems.EntraTenant, out var tenant)
                    && Guid.TryParse(tenant, out var tenantId))
                {
                    context.ProtocolMessage.IssuerAddress = context.ProtocolMessage.IssuerAddress
                        .Replace("/organizations/", $"/{tenantId}/", StringComparison.OrdinalIgnoreCase)
                        .Replace("/common/", $"/{tenantId}/", StringComparison.OrdinalIgnoreCase);
                }

                if (context.Properties.Items.TryGetValue(AuthItems.Flow, out var flow) && flow is AuthFlows.Test or AuthFlows.Invite)
                    context.ProtocolMessage.Prompt = "select_account";
            };

            options.Events.OnRemoteFailure = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("EntraAuthentication");
                logger.LogWarning(context.Failure, "Entra sign-in failed");
                context.Response.Redirect("/auth/error?reason=entra");
                context.HandleResponse();
                return Task.CompletedTask;
            };
        });

        return builder;
    }

    public const string ConsentCallbackPath = "/admin/sso/consent";

    public static string RedirectUri(IConfiguration configuration) =>
        SamlAuthentication.PublicBaseUrl(configuration) + (configuration["AzureAd:CallbackPath"] ?? "/signin-oidc");

    /// <summary>Lets a customer's Entra admin consent to the app for their whole tenant.</summary>
    public static string AdminConsentUrl(IConfiguration configuration, string tenantId, string state)
    {
        var instance = (configuration["AzureAd:Instance"] ?? "https://login.microsoftonline.com/").TrimEnd('/');
        var clientId = configuration["AzureAd:ClientId"] ?? "";
        var redirectUri = SamlAuthentication.PublicBaseUrl(configuration) + ConsentCallbackPath;
        return $"{instance}/{Uri.EscapeDataString(tenantId)}/adminconsent?client_id={Uri.EscapeDataString(clientId)}"
               + $"&redirect_uri={Uri.EscapeDataString(redirectUri)}&state={Uri.EscapeDataString(state)}";
    }
}
