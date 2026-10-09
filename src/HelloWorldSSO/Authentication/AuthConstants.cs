namespace HelloWorldSSO;

public static class AuthSchemes
{
    /// <summary>The application session. Only issued after tenant authorization succeeds.</summary>
    public const string App = "HelloWorldSSO";

    /// <summary>
    /// Short-lived cookie holding the raw result of an external (OIDC or SAML) sign-in until
    /// <see cref="Authentication.TenantAuthorizationService"/> has evaluated it.
    /// </summary>
    public const string External = "HelloWorldSSO.External";

    public const string Oidc = Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectDefaults.AuthenticationScheme;

    public const string Saml = Sustainsys.Saml2.AspNetCore2.Saml2Defaults.Scheme;
}

public static class AppClaims
{
    public const string UserId = "hw:user_id";
    public const string CustomerId = "hw:customer_id";
    public const string CustomerName = "hw:customer_name";
    public const string IdentityProvider = "hw:idp";
    public const string ExternalId = "hw:external_id";
    public const string Email = "hw:email";
    public const string ValidatedAt = "hw:validated_at";
}

public static class AuthPolicies
{
    public const string CustomerAdmin = "CustomerAdmin";
    public const string PlatformAdmin = "PlatformAdmin";
}

/// <summary>
/// Keys stored in <see cref="Microsoft.AspNetCore.Authentication.AuthenticationProperties.Items"/>.
/// These round-trip through the protected OIDC state / SAML relay state, so they cannot be
/// altered by the browser.
/// </summary>
public static class AuthItems
{
    public const string Flow = "hw.flow";
    public const string Scheme = "hw.scheme";
    public const string CustomerId = "hw.customer";
    public const string ConfigurationId = "hw.config";
    public const string InitiatorUserId = "hw.initiator";
    public const string InvitationToken = "hw.invite";
    public const string ReturnUrl = "hw.return";
    public const string EntraTenant = "hw.entra_tenant";

    /// <summary>Used by Sustainsys.Saml2 to select the identity provider.</summary>
    public const string SamlIdp = "idp";
}

public static class AuthFlows
{
    public const string Login = "login";
    public const string Test = "test";
    public const string Invite = "invite";
    public const string Operator = "operator";
}
