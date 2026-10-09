using HelloWorldSSO.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace HelloWorldSSO.Authentication;

public static class SsoLoginHelper
{
    public static (string Scheme, AuthenticationProperties Props) BuildChallenge(SsoConfiguration cfg, bool test)
    {
        var props = new AuthenticationProperties { RedirectUri = test ? "/Admin/Sso" : "/" };
        props.Items[AppClaims.PropType] = cfg.AuthenticationType;
        props.Items[AppClaims.PropCustomer] = cfg.CustomerId.ToString();
        if (test) props.Items[AppClaims.PropTest] = "1";
        if (cfg.AuthenticationType == AuthenticationTypes.EntraOidc)
        {
            props.Items[AppClaims.PropTenant] = cfg.EntraTenantId;
            return (OpenIdConnectDefaults.AuthenticationScheme, props);
        }
        props.Items["idp"] = cfg.SamlEntityId; // Sustainsys.Saml2 selects the IdP from this item
        return (SamlAuthentication.Scheme, props);
    }
}
