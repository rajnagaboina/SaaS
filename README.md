# SaaS — HelloWorldSSO

A multi-tenant ASP.NET Core (.NET 10) SaaS application with a customer-facing SSO portal. Each customer's administrator configures **Microsoft Entra ID (OIDC)** or **SAML 2.0**, tests it, and activates it without anyone editing configuration files. See [Design.md](Design.md) for the design.

## How it works

```
/login/{org} ──► Entra OIDC (Microsoft.Identity.Web) ─┐
             └─► SAML 2.0   (Sustainsys.Saml2)       ─┴─► "External" cookie (10 min)
                                                              │
                                              /auth/complete  ▼
                                         TenantAuthorizationService
                    IdP matches an active config? customer active? user allowed?
                                                              │
                                                              ▼
                                                   App session cookie ──► Hello World
```

Both protocols land in the same short-lived external cookie. They then pass through the same authorization gate before the real session is issued.

| Path | Who | Purpose |
| --- | --- | --- |
| `/login`, `/login/{slug}` | anyone | Pick your organization, then sign in with its active IdP |
| `/` | signed-in users | Hello World |
| `/admin/sso` | customer admins | Screen A: choose Entra ID or SAML; list configurations |
| `/admin/sso/entra/{id}` | customer admins | Screen B: tenant ID, admin-consent link, test, activate |
| `/admin/sso/saml/{id}` | customer admins | Screen C: SP details, metadata upload/URL, validate, test, activate |
| `/admin/users` | customer admins | Users, invitations, auto-provisioning toggle |
| `/platform` | platform operators | Create customers, invite their first admin, audit log |
| `/Saml2` | anyone | SP metadata (download for the customer's IdP) |
| `/Saml2/Acs` | IdPs | SAML Assertion Consumer Service |
| `/signin-oidc` | Entra | OIDC callback |

### Configuration lifecycle

`Pending → Testing → Active → Disabled`. Saving a valid configuration moves it to *Testing*. **Activate** is allowed only after a successful test sign-in against the *current* settings. Active configurations are read-only: to change one, create a new configuration, test and activate it, then disable the old one. A customer can have several configurations.

### Security controls

- **Admins come only from invitations.** These are single-use, expire after 7 days, and are stored as SHA-256 hashes. The signed-in email must match the invitation. Auto-provisioned users always get the `User` role.
- **Tenant allowlist.** An Entra sign-in is accepted only if its `tid` matches an active configuration. A SAML sign-in is accepted only if its issuer matches an active configuration and the response is signed by that configuration's certificates.
- **No hijacking of issuers.** An Entra tenant ID or SAML entity ID can belong to only one live configuration.
- **SAML.** Only SP-initiated sign-in is supported: unsolicited responses are rejected, `InResponseTo` is correlated, and replays are detected. Metadata is parsed with DTDs disabled and is never re-fetched at sign-in time.
- **SSRF-safe metadata fetch.** Only HTTPS on port 443, no IP literals and no redirects. The fetcher checks the resolved IP when connecting, so a DNS name that resolves to a private address is still rejected. Responses are capped at 1 MB with a 10 s timeout.
- **Tenant isolation.** Every query is scoped by the `CustomerId` claim, never by a URL parameter. Another customer's configuration ID returns 404.
- **Revocation.** Sessions are re-checked against the database every 5 minutes, so disabling a user or suspending a customer takes effect promptly.
- **Lockout recovery.** An invited admin can always sign in with the identity they were linked to, even if the customer's SSO is broken or disabled.
- **Audit log** records every configuration change, test, activation, sign-in, denial and invitation.

## Run locally

Requires the .NET 10 SDK. Local runs use SQLite and seed two demo customers: Contoso and Fabrikam.

```powershell
dotnet dev-certs https --trust          # once
dotnet run --project src/HelloWorldSSO --launch-profile https
```

Open https://localhost:7139/dev/login to sign in as a seeded user without an IdP. This page exists **only** in the Development environment. To use real Entra sign-in locally, set `AzureAd:ClientId` with `dotnet user-secrets`.

## Deploy to Azure

`infra/deploy.ps1` creates the multitenant Entra app registration and deploys `infra/main.bicep`. That provisions App Service (Linux, .NET 10), serverless Azure SQL with Entra-only auth, Key Vault, and Application Insights. The script then grants the web app's managed identity access to the database and publishes the app. There are no passwords or secrets: the app reaches SQL and Key Vault with its managed identity, and sign-in uses ID tokens.

```powershell
az login
./infra/deploy.ps1 -ResourceGroup rg-helloworldsso -Location eastus -NamePrefix hwsso
```

The deploying user becomes the SQL Entra admin and the first platform operator (`Platform:Operators`, written as `tenantId:objectId`).

## Database migrations

Migrations target SQL Server and are applied at startup (`Database:MigrateOnStartup`).

```powershell
dotnet tool restore
cd src/HelloWorldSSO
dotnet ef migrations add <Name> -o Data/Migrations
```

## Not yet implemented

- SAML single logout and encrypted assertions. Encrypted assertions need an SP certificate, which would go in Key Vault.
- Data-protection keys shared across instances. They are needed before scaling out beyond one App Service instance (Blob Storage plus a Key Vault key).
- Email delivery of invitations. Today the link is shown once to the person who created it.
- A custom domain such as `hello.yourapp.com`. Until then the app runs at `*.azurewebsites.net`.
