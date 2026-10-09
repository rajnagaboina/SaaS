namespace HelloWorldSSO.Authentication;

public static class AppClaims
{
    public const string CustomerId = "app:customer_id";
    public const string CustomerName = "app:customer_name";
    public const string UserId = "app:user_id";
    public const string IdentityProvider = "app:idp";

    // Keys stored in AuthenticationProperties (protected by the OIDC/SAML state) to correlate a login with its customer.
    public const string PropType = "sso_type";
    public const string PropCustomer = "sso_customer";
    public const string PropTenant = "sso_tenant";
    public const string PropTest = "sso_test";
}

public static class Policies
{
    public const string TenantAdmin = "TenantAdmin";
}
