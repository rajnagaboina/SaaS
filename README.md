# SaaS
Saas Application to provide to vendors with SAML and OIDC

## HelloWorldSSO

ASP.NET Core (.NET 10) Razor Pages app with per-customer SSO (Microsoft Entra ID OIDC and SAML 2.0 via Sustainsys.Saml2) and a customer admin portal at `/Admin/Sso`.

- Both protocols sign in to one cookie; `OnSigningIn` runs `TenantAuthorizationService` (customer active, IdP/tenant matches the customer's configuration, user provisioned, admin-only test logins for inactive configs).
- SAML metadata is parsed strictly (no DTD, https SSO URL, valid signing cert); metadata URLs are fetched with SSRF protections.
- Configure `AzureAd` (ClientId, plus a client secret/certificate from a secret store such as Key Vault), `ConnectionStrings:DefaultConnection` (SQL Server; in-memory DB if empty) and `App:BaseUrl`.
- Development seeds customer `contoso` with admin `Seed:AdminEmail` and a dev-only sign-in on `/Login`. In production, provision customers/administrators through a controlled process (EF migrations are not yet included).

Run tests: `dotnet test`.
