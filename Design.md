A SaaS-ready ASP.NET Core application with a customer-facing SSO configuration portal**, supporting both Microsoft Entra ID (OIDC) and enterprise SAML 2.0.

Each customer administrator will be able to configure their organization's SSO settings, test the connection, and activate SSO without you manually editing application configuration files.

# 1. What we are going to build

Let's call the application `SaaS`.

The application will have four main components:

| Component                 | Purpose                                                              |
| ------------------------- | -------------------------------------------------------------------- |
| Customer login page       | Allows users to sign in using their organization's identity provider |
| SSO administration portal | Allows customer administrators to configure authentication           |
| Authentication service    | Handles Entra ID OIDC and SAML authentication                        |
| Tenant management service | Controls which customers and users can access the application        |

### Example customer experience

Suppose you have two customers.

**Contoso**

* Uses Microsoft Entra ID.
* Configures Entra SSO in your application.
* Its employees sign in using their Microsoft work accounts.

**Fabrikam**

* Uses an identity provider that supports SAML 2.0.
* Uploads its SAML metadata to your application.
* Its employees sign in through that identity provider.

Both customers use the same application.

```text
                  HelloWorldSSO
               hello.yourapp.com
                        |
              +---------+---------+
              |                   |
              v                   v
         Contoso Login       Fabrikam Login
              |                   |
              v                   v
       Microsoft Entra ID    SAML Identity Provider
              |                   |
              +---------+---------+
                        |
                        v
                 Authentication
                        |
                        v
                Tenant Authorization
                        |
                        v
                   Hello World
```

---

# 2. Technology stack

I recommend the following stack for the first implementation.

| Technology               | Purpose                                                   |
| ------------------------ | --------------------------------------------------------- |
| .NET 10                  | Application framework                                     |
| ASP.NET Core Razor Pages | Web UI                                                    |
| Microsoft Identity Web   | Microsoft Entra ID authentication                         |
| OpenID Connect           | Entra authentication protocol                             |
| Sustainsys.Saml2         | SAML integration                                          |
| Entity Framework Core    | Database access                                           |
| SQL Server               | Customer and SSO configuration storage                    |
| ASP.NET Core cookies     | Application sessions                                      |
| Azure Key Vault          | Secure storage of credentials and sensitive configuration |

Official references:

* [Microsoft Identity Web](https://learn.microsoft.com/en-us/entra/msidweb/?utm_source=chatgpt.com)
* [ASP.NET Core authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/?utm_source=chatgpt.com)
* [Sustainsys.Saml2](https://saml2.sustainsys.com/?utm_source=chatgpt.com)
* [Entity Framework Core](https://learn.microsoft.com/en-us/ef/core/?utm_source=chatgpt.com)

One architectural detail is important: the Entra OIDC handler and SAML handler need different protocol-specific configuration, but both should ultimately establish the same application session and pass through the same tenant authorization checks.

---

# 3. Design the customer-facing SSO portal

Create an administration page at:

`https://hello.yourapp.com/admin/sso`

Only authorized administrators should be able to access this page.

The portal will have the following screens.

## Screen A: Select authentication method

```text
+--------------------------------------------------+
|             HelloWorldSSO                        |
|             SSO Configuration                    |
+--------------------------------------------------+
|                                                  |
|  Organization: Contoso                           |
|                                                  |
|  Choose your authentication provider:            |
|                                                  |
|  ( ) Microsoft Entra ID                          |
|                                                  |
|  ( ) SAML 2.0                                     |
|                                                  |
|                         [Continue]               |
+--------------------------------------------------+
```

The available options should be controlled by your product's supported authentication methods.

## Screen B: Microsoft Entra ID configuration

When the administrator selects Entra ID, display the information needed to configure their tenant.

```text
+--------------------------------------------------+
|          Microsoft Entra ID SSO                  |
+--------------------------------------------------+
|                                                  |
|  Customer Tenant ID:                             |
|  [________________________________]              |
|                                                  |
|  Authentication method: OpenID Connect           |
|                                                  |
|  Redirect URI:                                   |
|  https://hello.yourapp.com/signin-oidc           |
|                                                  |
|  [Save Configuration]                            |
|  [Test Connection]                               |
|                                                  |
+--------------------------------------------------+
```

For this design, the application uses **your existing multitenant Entra app registration**.

Customers generally do not need to create a separate OIDC app registration just to sign in to your SaaS application. Their tenant-specific enterprise application and consent establish their relationship with your application.

The customer's tenant ID helps you associate the configuration with the correct organization.

The configuration screen should explain that the administrator may need to grant consent and configure user assignment in their tenant.

## Screen C: SAML configuration

When the administrator selects SAML, show:

```text
+--------------------------------------------------+
|               SAML SSO Setup                     |
+--------------------------------------------------+
|                                                  |
|  Service Provider Entity ID:                     |
|  https://hello.yourapp.com/saml                  |
|                                                  |
|  Assertion Consumer Service URL:                 |
|  https://hello.yourapp.com/Saml/Acs              |
|                                                  |
|  Service Provider Metadata:                      |
|  [Download Metadata]                             |
|                                                  |
|  Identity Provider Metadata:                     |
|                                                  |
|  [Upload XML Metadata]                           |
|                                                  |
|  OR                                              |
|                                                  |
|  Metadata URL:                                   |
|  [________________________________]              |
|                                                  |
|  [Validate Configuration]                        |
|  [Test Login]                                    |
|  [Activate SSO]                                  |
|                                                  |
+--------------------------------------------------+
```

The URLs shown are examples. The actual endpoints must match the selected SAML library's configuration.

### How SAML configuration works

Your application acts as the **Service Provider (SP)**.

Your customer's identity provider acts as the **Identity Provider (IdP)**.

Your application provides its SP metadata. The customer configures their IdP using that metadata and gives you their IdP metadata.

Your application uses the trusted IdP metadata to establish the SAML integration.

The metadata can include information such as:

* Identity provider entity ID.
* SSO endpoint.
* Signing certificates.
* Supported SAML bindings.

You should validate and review metadata before activating the connection. In particular, a metadata URL must not be fetched without appropriate protections against server-side request forgery.

---

# 4. Design the database

For a SaaS application, customer configuration belongs in a database rather than being hardcoded in `appsettings.json`.

I recommend starting with three tables.

## Table 1: Customers

Stores your customer organizations.

| Column    | Type     | Example              |
| --------- | -------- | -------------------- |
| Id        | GUID     | Internal customer ID |
| Name      | String   | Contoso              |
| Status    | String   | Active               |
| CreatedAt | DateTime | Creation timestamp   |

## Table 2: SsoConfigurations

Stores the authentication configuration for each customer.

| Column             | Type             | Example                         |
| ------------------ | ---------------- | ------------------------------- |
| Id                 | GUID             | Configuration ID                |
| CustomerId         | GUID             | Associated customer             |
| AuthenticationType | String           | EntraOIDC or SAML               |
| EntraTenantId      | String, nullable | Customer's tenant ID            |
| SamlEntityId       | String, nullable | IdP entity ID                   |
| SamlMetadata       | Text, nullable   | Validated metadata or reference |
| Status             | String           | Pending, Active, Disabled       |
| CreatedAt          | DateTime         | Creation timestamp              |

For production, storing a metadata reference and normalized configuration may be preferable to keeping raw metadata as the sole source of truth.

A customer might eventually need more than one identity-provider configuration. Therefore, don't assume the database must permanently enforce exactly one SSO configuration per customer.

## Table 3: CustomerUsers

Stores application-level customer membership.

| Column           | Type   | Example                        |
| ---------------- | ------ | ------------------------------ |
| Id               | GUID   | Internal user ID               |
| CustomerId       | GUID   | Customer ID                    |
| IdentityProvider | String | EntraOIDC                      |
| ExternalUserId   | String | Validated provider-specific ID |
| Email            | String | User email                     |
| Role             | String | Admin or User                  |
| Status           | String | Active                         |

Use a stable provider-specific identity for account linking. For Entra ID, a combination of tenant ID and object ID is a useful identifier. For SAML, use the configured issuer and a stable subject identifier.

Email alone should not be treated as a unique, immutable user identity.

**Important:** Do not let someone become a customer administrator merely because they successfully signed in. Provision administrators through a trusted invitation, an existing administrative process, or another controlled mechanism.

---

# 5. Create the application

Let's establish the project structure first.

### Step 1: Create the project

Install the .NET 10 SDK, then run:

```bash
dotnet new webapp --auth None -n HelloWorldSSO

cd HelloWorldSSO
```

Add the Entra authentication packages:

```bash
dotnet add package Microsoft.Identity.Web
dotnet add package Microsoft.Identity.Web.UI
```

Add Entity Framework Core for SQL Server:

```bash
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package Microsoft.EntityFrameworkCore.Design
```

For SAML, use the supported ASP.NET Core integration from Sustainsys.Saml2. Check its documentation and package compatibility before selecting an exact version.

I recommend pinning compatible package versions rather than blindly installing the newest version of every dependency.

### Step 2: Create the project folders

Create these folders:

```text
HelloWorldSSO/
│
├── Authentication/
│   ├── EntraAuthentication.cs
│   ├── SamlAuthentication.cs
│   └── TenantAuthorizationService.cs
│
├── Data/
│   └── ApplicationDbContext.cs
│
├── Models/
│   ├── Customer.cs
│   ├── SsoConfiguration.cs
│   └── CustomerUser.cs
│
├── Pages/
│   ├── Index.cshtml
│   └── Admin/
│       └── Sso.cshtml
│
├── Services/
│   ├── CustomerService.cs
│   └── SsoConfigurationService.cs
│
├── Program.cs
└── appsettings.json
```

This structure separates the web UI, authentication, database, and customer management logic.

It is a starting point, not a complete implementation of both authentication protocols.

---

# 6. Configure Entra ID

In the Microsoft Entra admin center, register your application with:

* Supported account type: Accounts in any organizational directory.
* Platform: Web.
* Redirect URI: `https://localhost:<your-port>/signin-oidc`.

Use the actual HTTPS port reported by your application.

Your `appsettings.json` will contain:

```json
{
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "organizations",
    "ClientId": "YOUR-APPLICATION-CLIENT-ID",
    "CallbackPath": "/signin-oidc"
  },
  "ConnectionStrings": {
    "DefaultConnection": "YOUR-SECURE-CONNECTION-STRING"
  }
}
```

The `organizations` authority supports organizational accounts across Microsoft Entra tenants.

However, this is only the authentication configuration. You still need to validate that the authenticated tenant is approved to access your SaaS application.

For production, store database credentials and other secrets in an appropriate secret manager rather than committing them to source control.

---

# 7. Handle both authentication methods

Your application should maintain separate authentication handlers for OIDC and SAML.

Conceptually, the configuration is:

```text
ASP.NET Core Authentication
│
├── Application Cookie
│
├── Entra OIDC Handler
│
└── SAML Handler
```

When a customer selects Entra ID, your application initiates OIDC authentication.

When a customer selects SAML, your application initiates the SAML authentication flow using that customer's registered SAML configuration.

After successful authentication, the application establishes its session and performs tenant authorization.

The precise ASP.NET Core registration code for the SAML handler depends on the Sustainsys.Saml2 package version and its ASP.NET Core integration. It should be implemented using the library's supported configuration APIs, rather than guessing handler names or endpoints.

For both flows, the authorization layer should verify:

1. The authentication response is valid.
2. The identity provider matches the customer's configured provider.
3. The customer is active.
4. The user is authorized for that customer.
5. The requested application resource belongs to the same customer.

Only then should the user see the protected Hello World page.

---

# 8. Implement the Hello World page

Once authentication and tenant authorization have been configured, the page itself can remain simple.

For example, in `Pages/Index.cshtml`:

```cshtml
@page
@model IndexModel

@{
    ViewData["Title"] = "Hello World";
}

<div class="text-center">
    <h1>Hello, @User.Identity?.Name!</h1>

    <p>Welcome to HelloWorldSSO.</p>

    <p>You are authenticated.</p>
</div>
```

This page is intended to be protected by your application's authentication policy.

The authentication layer determines how the user signs in; the page simply displays the authenticated identity.

For production, explicitly map validated identity claims to your application's user model instead of assuming every identity provider supplies the same claims.

---

# 9. Add an SSO configuration workflow

Your customer-facing configuration portal should have the following lifecycle:

```text
Customer Administrator
          |
          v
Select Authentication Type
          |
          +----------------------+
          |                      |
          v                      v
     Entra OIDC               SAML 2.0
          |                      |
          v                      v
  Configure Tenant       Upload/Import Metadata
          |                      |
          v                      v
  Validate Configuration / Trust
          |                      |
          +----------+-----------+
                     |
                     v
                Test Login
                     |
                     v
              Administrator Review
                     |
                     v
               Activate SSO
                     |
                     v
              Users Can Sign In
```

Recommended configuration statuses:

* **Not configured:** No SSO setup exists.
* **Pending:** The administrator has started configuration.
* **Testing:** Configuration validation is in progress.
* **Active:** The configuration is approved for sign-in.
* **Disabled:** The integration has been deactivated.

For SAML, validate metadata, signatures, issuer, audience, recipient, destination, timestamps, and authentication-request correlation as appropriate. Also ensure that customer-specific configuration cannot be substituted during a login flow.

For Entra, validate the OIDC response and enforce your tenant allowlist.

---

# 10. How the customer onboarding experience should work

A production onboarding workflow should look like this:

**Step 1:** You create a customer organization in your SaaS administration portal.

**Step 2:** You invite the customer's administrator.

**Step 3:** The administrator signs in and opens the SSO configuration page.

**Step 4:** The administrator selects either Microsoft Entra ID or SAML.

**Step 5:** The administrator configures the relevant settings.

**Step 6:** Your application validates the configuration and allows a test sign-in.

**Step 7:** After successful testing and any required administrative approval, the administrator activates SSO.

**Step 8:** Your application accepts users from that customer's approved identity provider and applies the appropriate access policies.

This gives you a repeatable onboarding process without manually changing application files for every customer.

---

# 11. Important production security controls

Before making the SSO portal available to customers, implement these controls:

| Control                         | Why it matters                                                        |
| ------------------------------- | --------------------------------------------------------------------- |
| Authorized administrator access | Prevents unauthorized SSO configuration changes                       |
| Tenant allowlist                | Prevents arbitrary Entra tenants from accessing your SaaS application |
| SAML signature validation       | Prevents forged SAML assertions                                       |
| OIDC token validation           | Establishes trust in the identity provider's authentication response  |
| Secure metadata handling        | Prevents untrusted metadata from introducing unsafe configuration     |
| Tenant isolation                | Prevents users from accessing another customer's data                 |
| Secure secret storage           | Protects client secrets, private keys, and other credentials          |
| Audit logs                      | Records configuration changes and authentication events               |
| Safe configuration changes      | Prevents untested changes from unexpectedly locking out customers     |

One additional consideration: if a customer activates SSO-only access, retain a carefully controlled recovery mechanism for authorized administrators. Otherwise, an incorrect configuration could lock the organization out of its own administration portal.

---

# 12. What I recommend building first

For the first working version, I would implement these deliverables in order:

| Deliverable                     | Result                                                          |
| ------------------------------- | --------------------------------------------------------------- |
| 1. Hello World application      | A working ASP.NET Core website                                  |
| 2. Entra ID SSO                 | Organizational users can sign in                                |
| 3. Customer database            | Each customer has an independent record                         |
| 4. SSO administration page      | Administrators can choose Entra or SAML                         |
| 5. Entra configuration workflow | Administrators can register and test their tenant configuration |
| 6. SAML configuration workflow  | Administrators can upload metadata and test federation          |
| 7. Tenant authorization         | Only approved customers and users can access the application    |

**My recommendation is to get Entra OIDC working first, then add SAML through a supported SAML library, while building the database and customer administration model to accommodate both from the beginning.**

This reduces implementation risk and makes it easier to test the two authentication flows independently.

The next step would be to generate a complete runnable .NET 10 solution containing the Hello World page, customer database models, SSO administration UI, Entra OIDC authentication, and the SAML integration scaffold.
