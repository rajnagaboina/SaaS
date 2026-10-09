using System.Text.RegularExpressions;
using HelloWorldSSO.Data;
using HelloWorldSSO.Models;
using Microsoft.EntityFrameworkCore;

namespace HelloWorldSSO.Services;

public class SsoConfigurationException(string message) : Exception(message);

public class SsoConfigurationService(ApplicationDbContext db, SafeMetadataFetcher fetcher)
{
    public Task<List<SsoConfiguration>> ListAsync(Guid customerId) =>
        db.SsoConfigurations.Where(c => c.CustomerId == customerId).OrderByDescending(c => c.CreatedAt).ToListAsync();

    public Task<SsoConfiguration?> GetAsync(Guid customerId, Guid id) =>
        db.SsoConfigurations.FirstOrDefaultAsync(c => c.Id == id && c.CustomerId == customerId);

    public async Task<SsoConfiguration> SaveEntraAsync(Guid customerId, string tenantId)
    {
        if (!Guid.TryParse(tenantId?.Trim(), out var tid))
            throw new SsoConfigurationException("Tenant ID must be a GUID.");
        var normalized = tid.ToString("D");
        if (tid == Guid.Empty)
            throw new SsoConfigurationException("Tenant ID must be a GUID.");

        // Each Entra tenant may belong to only one customer (tenant allowlist integrity).
        var taken = await db.SsoConfigurations.AnyAsync(c => c.EntraTenantId == normalized
            && c.CustomerId != customerId && c.Status != SsoStatus.Disabled);
        if (taken) throw new SsoConfigurationException("This tenant is already registered to another organization.");

        var cfg = await FindEditable(customerId, AuthenticationTypes.EntraOidc);
        cfg.EntraTenantId = normalized;
        Reset(cfg);
        await db.SaveChangesAsync();
        return cfg;
    }

    public async Task<SsoConfiguration> SaveSamlAsync(Guid customerId, string? metadataXml, string? metadataUrl)
    {
        string xml;
        if (!string.IsNullOrWhiteSpace(metadataXml)) xml = metadataXml;
        else if (!string.IsNullOrWhiteSpace(metadataUrl)) xml = await fetcher.FetchAsync(metadataUrl.Trim());
        else throw new SsoConfigurationException("Provide metadata XML or a metadata URL.");

        var info = SamlMetadataParser.Parse(xml);

        // The IdP entity ID identifies the customer during ACS processing, so it must be unambiguous.
        var taken = await db.SsoConfigurations.AnyAsync(c => c.SamlEntityId == info.EntityId
            && c.CustomerId != customerId && c.Status != SsoStatus.Disabled);
        if (taken) throw new SsoConfigurationException("This identity provider is already registered to another organization.");

        var cfg = await FindEditable(customerId, AuthenticationTypes.Saml);
        cfg.SamlEntityId = info.EntityId;
        cfg.SamlSingleSignOnUrl = info.SingleSignOnUrl;
        cfg.SamlSigningCertificates = string.Join('\n', info.SigningCertificates);
        cfg.SamlMetadata = xml;
        Reset(cfg);
        await db.SaveChangesAsync();
        return cfg;
    }

    public async Task MarkTestSucceededAsync(SsoConfiguration cfg)
    {
        cfg.LastTestSucceededAt = DateTime.UtcNow;
        if (cfg.Status is SsoStatus.Pending or SsoStatus.Testing) cfg.Status = SsoStatus.Testing;
        await db.SaveChangesAsync();
    }

    public async Task ActivateAsync(Guid customerId, Guid id)
    {
        var cfg = await GetAsync(customerId, id) ?? throw new SsoConfigurationException("Configuration not found.");
        if (cfg.LastTestSucceededAt is null)
            throw new SsoConfigurationException("A successful test login is required before activation.");
        if (cfg.Status is not (SsoStatus.Pending or SsoStatus.Testing))
            throw new SsoConfigurationException("Only a pending or testing configuration can be activated.");
        var previous = await db.SsoConfigurations
            .Where(c => c.CustomerId == customerId && c.Status == SsoStatus.Active).ToListAsync();
        foreach (var p in previous) p.Status = SsoStatus.Disabled;
        cfg.Status = SsoStatus.Active;
        await db.SaveChangesAsync();
    }

    public async Task DisableAsync(Guid customerId, Guid id)
    {
        var cfg = await GetAsync(customerId, id) ?? throw new SsoConfigurationException("Configuration not found.");
        cfg.Status = SsoStatus.Disabled;
        await db.SaveChangesAsync();
    }

    private static void Reset(SsoConfiguration cfg)
    {
        // Any change invalidates a previous test.
        cfg.Status = SsoStatus.Pending;
        cfg.LastTestSucceededAt = null;
    }

    // Edits never touch an Active configuration: they go into a new draft so a bad change cannot lock the customer out.
    private async Task<SsoConfiguration> FindEditable(Guid customerId, string type)
    {
        var cfg = await db.SsoConfigurations.FirstOrDefaultAsync(c => c.CustomerId == customerId
            && c.AuthenticationType == type
            && (c.Status == SsoStatus.Pending || c.Status == SsoStatus.Testing));
        if (cfg is null)
        {
            cfg = new SsoConfiguration { CustomerId = customerId, AuthenticationType = type };
            db.SsoConfigurations.Add(cfg);
        }
        return cfg;
    }
}
