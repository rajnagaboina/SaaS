using HelloWorldSSO.Authentication;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Services;

public record SsoOperationResult(bool Succeeded, IReadOnlyList<string> Errors, IReadOnlyList<string> Warnings)
{
    public static SsoOperationResult Ok(IReadOnlyList<string>? warnings = null) => new(true, [], warnings ?? []);
    public static SsoOperationResult Fail(params string[] errors) => new(false, errors, []);
}

/// <summary>
/// Owns the SSO configuration lifecycle: Pending → Testing → Active → Disabled. Every method
/// takes the caller's customer ID, so one customer can never read or change another's settings.
/// Active configurations are read-only; changes are made in a new configuration that is tested
/// and activated alongside the old one, so a mistake cannot lock users out.
/// </summary>
public class SsoConfigurationService(
    ApplicationDbContext db,
    AuditService audit,
    SamlMetadataParser metadataParser,
    SafeMetadataFetcher metadataFetcher,
    SamlIdentityProviderStore samlStore)
{
    public Task<List<SsoConfiguration>> ListAsync(Guid customerId) =>
        db.SsoConfigurations.AsNoTracking().Where(c => c.CustomerId == customerId)
            .OrderBy(c => c.Status == SsoStatus.Disabled).ThenByDescending(c => c.CreatedAt).ToListAsync();

    public Task<List<SsoConfiguration>> ListActiveAsync(Guid customerId) =>
        db.SsoConfigurations.AsNoTracking()
            .Where(c => c.CustomerId == customerId && c.Status == SsoStatus.Active).ToListAsync();

    public Task<SsoConfiguration?> GetAsync(Guid customerId, Guid id) =>
        db.SsoConfigurations.FirstOrDefaultAsync(c => c.Id == id && c.CustomerId == customerId);

    public async Task<SsoConfiguration> CreateAsync(Guid customerId, string authenticationType)
    {
        if (!AuthenticationTypes.IsValid(authenticationType))
            throw new ArgumentException("Unsupported authentication type.", nameof(authenticationType));

        var config = new SsoConfiguration { CustomerId = customerId, AuthenticationType = authenticationType };
        db.SsoConfigurations.Add(config);
        audit.Record(customerId, "Sso.Created", $"{authenticationType} config={config.Id}");
        await db.SaveChangesAsync();
        return config;
    }

    public async Task<SsoOperationResult> SaveEntraAsync(Guid customerId, Guid id, string? tenantId)
    {
        var config = await GetEditableAsync(customerId, id, AuthenticationTypes.EntraOidc);
        if (config.Error is not null) return SsoOperationResult.Fail(config.Error);

        if (!Guid.TryParse(tenantId?.Trim(), out var parsed) || parsed == Guid.Empty)
            return SsoOperationResult.Fail("Enter your Directory (tenant) ID, a GUID such as 72f988bf-86f1-41af-91ab-2d7cd011db47.");
        var normalized = parsed.ToString();

        var inUse = await db.SsoConfigurations.AnyAsync(c => c.Id != id && c.Status != SsoStatus.Disabled
            && c.AuthenticationType == AuthenticationTypes.EntraOidc && c.EntraTenantId == normalized);
        if (inUse)
            return SsoOperationResult.Fail("This tenant is already registered with another configuration. Contact support if you believe this is a mistake.");

        var c = config.Config!;
        c.EntraTenantId = normalized;
        MarkChanged(c, SsoStatus.Testing);
        audit.Record(customerId, "Sso.EntraSaved", $"config={id} tenant={normalized}");
        await db.SaveChangesAsync();
        return SsoOperationResult.Ok();
    }

    public async Task<SsoOperationResult> ImportSamlMetadataAsync(Guid customerId, Guid id, string? xml, string? metadataUrl, CancellationToken cancellationToken)
    {
        var config = await GetEditableAsync(customerId, id, AuthenticationTypes.Saml);
        if (config.Error is not null) return SsoOperationResult.Fail(config.Error);

        if (string.IsNullOrWhiteSpace(xml))
        {
            if (string.IsNullOrWhiteSpace(metadataUrl))
                return SsoOperationResult.Fail("Upload a metadata XML file or enter a metadata URL.");
            var (fetched, error) = await metadataFetcher.FetchAsync(metadataUrl.Trim(), cancellationToken);
            if (error is not null) return SsoOperationResult.Fail(error);
            xml = fetched;
        }
        else
        {
            metadataUrl = null;
        }

        var parsed = metadataParser.Parse(xml!);
        if (!parsed.IsValid)
            return new SsoOperationResult(false, parsed.Errors, []);
        var metadata = parsed.Metadata!;

        // An IdP entity ID identifies exactly one live configuration; otherwise one customer
        // could register another's IdP issuer with their own certificate.
        var inUse = await db.SsoConfigurations.AnyAsync(c => c.Id != id && c.Status != SsoStatus.Disabled
            && c.AuthenticationType == AuthenticationTypes.Saml && c.SamlEntityId == metadata.EntityId);
        if (inUse)
            return SsoOperationResult.Fail($"The identity provider '{metadata.EntityId}' is already registered with another configuration.");

        var c = config.Config!;
        var previousEntityId = c.SamlEntityId;
        c.SamlEntityId = metadata.EntityId;
        c.SamlMetadata = xml;
        c.SamlMetadataUrl = metadataUrl?.Trim();
        c.SamlSsoUrl = metadata.SsoUrl;
        c.SamlSsoBinding = metadata.SsoBinding;
        c.SamlSigningCertificates = string.Join('\n', metadata.SigningCertificates.Select(x => Convert.ToBase64String(x.RawData)));
        MarkChanged(c, SsoStatus.Testing);
        audit.Record(customerId, "Sso.SamlMetadataImported",
            $"config={id} entity={metadata.EntityId} sso={metadata.SsoUrl} certs={string.Join(',', metadata.SigningCertificates.Select(x => x.Thumbprint))}");
        await db.SaveChangesAsync();

        samlStore.Invalidate(previousEntityId);
        samlStore.Invalidate(c.SamlEntityId);
        return SsoOperationResult.Ok(metadata.Warnings);
    }

    public async Task<SsoOperationResult> ActivateAsync(Guid customerId, Guid id)
    {
        var config = await GetAsync(customerId, id);
        if (config is null) return SsoOperationResult.Fail("Configuration not found.");
        if (!config.CanActivate)
            return SsoOperationResult.Fail("Run a successful test sign-in with the current settings before activating.");

        config.Status = SsoStatus.Active;
        config.ActivatedAt = DateTime.UtcNow;
        audit.Record(customerId, "Sso.Activated", $"config={id} {config.AuthenticationType}");
        await db.SaveChangesAsync();
        samlStore.Invalidate(config.SamlEntityId);
        return SsoOperationResult.Ok();
    }

    public async Task<SsoOperationResult> DisableAsync(Guid customerId, Guid id)
    {
        var config = await GetAsync(customerId, id);
        if (config is null) return SsoOperationResult.Fail("Configuration not found.");

        var wasLastActive = config.Status == SsoStatus.Active
            && !await db.SsoConfigurations.AnyAsync(c => c.CustomerId == customerId && c.Id != id && c.Status == SsoStatus.Active);

        config.Status = SsoStatus.Disabled;
        config.UpdatedAt = DateTime.UtcNow;
        audit.Record(customerId, "Sso.Disabled", $"config={id} {config.AuthenticationType}");
        await db.SaveChangesAsync();
        samlStore.Invalidate(config.SamlEntityId);

        return SsoOperationResult.Ok(wasLastActive
            ? ["This was your organization's only active SSO configuration. Users cannot sign in until another is activated; invited administrators can still sign in with their linked account."]
            : null);
    }

    private async Task<(SsoConfiguration? Config, string? Error)> GetEditableAsync(Guid customerId, Guid id, string expectedType)
    {
        var config = await GetAsync(customerId, id);
        if (config is null || config.AuthenticationType != expectedType)
            return (null, "Configuration not found.");
        if (config.Status is SsoStatus.Active or SsoStatus.Disabled)
            return (null, $"{config.Status} configurations cannot be edited. Create a new configuration instead.");
        return (config, null);
    }

    private static void MarkChanged(SsoConfiguration config, string status)
    {
        config.Status = status;
        config.UpdatedAt = DateTime.UtcNow;
        config.LastTestSucceeded = false;
        config.LastTestedAt = null;
        config.LastTestMessage = null;
    }
}
