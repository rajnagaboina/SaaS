using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace HelloWorldSSO.Services;

public record SamlIdpMetadata(
    string EntityId,
    string SsoUrl,
    string SsoBinding,
    IReadOnlyList<X509Certificate2> SigningCertificates,
    IReadOnlyList<string> Warnings);

public record SamlMetadataParseResult(SamlIdpMetadata? Metadata, IReadOnlyList<string> Errors)
{
    public bool IsValid => Metadata is not null && Errors.Count == 0;
}

/// <summary>
/// Parses untrusted IdP metadata into a normalized configuration. The XML reader prohibits
/// DTDs and external resolution, and every value is checked before it can be used.
/// </summary>
public class SamlMetadataParser(IHostEnvironment environment)
{
    public const int MaxMetadataBytes = 1024 * 1024;

    private static readonly XNamespace Md = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static readonly XNamespace Ds = "http://www.w3.org/2000/09/xmldsig#";
    private const string ProtocolSaml2 = "urn:oasis:names:tc:SAML:2.0:protocol";
    private const string BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    private const string BindingPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    public SamlMetadataParseResult Parse(string xml)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        if (string.IsNullOrWhiteSpace(xml))
            return Fail("Metadata is empty.");
        if (xml.Length > MaxMetadataBytes)
            return Fail("Metadata exceeds the 1 MB size limit.");

        XDocument doc;
        try
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaxMetadataBytes,
                IgnoreComments = true,
            };
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            doc = XDocument.Load(reader);
        }
        catch (XmlException ex)
        {
            return Fail($"Metadata is not well-formed XML: {ex.Message}");
        }

        var root = doc.Root;
        if (root is null)
            return Fail("Metadata has no root element.");

        // Accept an EntitiesDescriptor only if it contains exactly one IdP.
        XElement? entity = root.Name == Md + "EntityDescriptor" ? root : null;
        if (root.Name == Md + "EntitiesDescriptor")
        {
            var idpEntities = root.Descendants(Md + "EntityDescriptor")
                .Where(e => e.Element(Md + "IDPSSODescriptor") is not null).ToList();
            if (idpEntities.Count != 1)
                return Fail("Metadata aggregate must contain exactly one identity provider.");
            entity = idpEntities[0];
        }
        if (entity is null)
            return Fail("Root element must be a SAML 2.0 md:EntityDescriptor.");

        var entityId = entity.Attribute("entityID")?.Value?.Trim();
        if (string.IsNullOrEmpty(entityId))
            errors.Add("EntityDescriptor is missing entityID.");
        else if (entityId.Length > 1024)
            errors.Add("entityID is too long.");

        CheckValidUntil(entity.Attribute("validUntil")?.Value ?? root.Attribute("validUntil")?.Value, errors);

        var idp = entity.Element(Md + "IDPSSODescriptor");
        if (idp is null)
            return Fail([.. errors, "Metadata does not contain an IDPSSODescriptor; is this SP metadata by mistake?"]);

        var protocols = idp.Attribute("protocolSupportEnumeration")?.Value ?? "";
        if (!protocols.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains(ProtocolSaml2))
            errors.Add("IdP does not advertise SAML 2.0 protocol support.");

        // Prefer HTTP-Redirect for AuthnRequests, fall back to HTTP-POST.
        var ssoServices = idp.Elements(Md + "SingleSignOnService").ToList();
        var sso = ssoServices.FirstOrDefault(s => s.Attribute("Binding")?.Value == BindingRedirect)
                  ?? ssoServices.FirstOrDefault(s => s.Attribute("Binding")?.Value == BindingPost);
        string ssoUrl = "", ssoBinding = "";
        if (sso is null)
        {
            errors.Add("No SingleSignOnService with HTTP-Redirect or HTTP-POST binding was found.");
        }
        else
        {
            ssoUrl = sso.Attribute("Location")?.Value?.Trim() ?? "";
            ssoBinding = sso.Attribute("Binding")!.Value == BindingRedirect ? "HttpRedirect" : "HttpPost";
            if (!Uri.TryCreate(ssoUrl, UriKind.Absolute, out var uri))
                errors.Add("SingleSignOnService Location is not an absolute URL.");
            else if (uri.Scheme != Uri.UriSchemeHttps && !(environment.IsDevelopment() && uri.IsLoopback))
                errors.Add("SingleSignOnService Location must use HTTPS.");
        }

        var certs = new List<X509Certificate2>();
        foreach (var key in idp.Elements(Md + "KeyDescriptor"))
        {
            var use = key.Attribute("use")?.Value;
            if (use is not null && use != "signing")
                continue;
            foreach (var certEl in key.Descendants(Ds + "X509Certificate"))
            {
                try
                {
                    var raw = Convert.FromBase64String(string.Concat(certEl.Value.Where(c => !char.IsWhiteSpace(c))));
                    var cert = X509CertificateLoader.LoadCertificate(raw);
                    if (cert.NotAfter < DateTime.UtcNow)
                        warnings.Add($"Signing certificate {cert.Thumbprint} expired on {cert.NotAfter:yyyy-MM-dd}.");
                    else if (cert.NotAfter < DateTime.UtcNow.AddDays(30))
                        warnings.Add($"Signing certificate {cert.Thumbprint} expires on {cert.NotAfter:yyyy-MM-dd}.");
                    if (certs.All(c => c.Thumbprint != cert.Thumbprint))
                        certs.Add(cert);
                }
                catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException)
                {
                    errors.Add("A signing certificate in the metadata could not be parsed.");
                }
            }
        }
        if (certs.Count == 0)
            errors.Add("No signing certificate was found; assertions could not be verified.");
        else if (certs.All(c => c.NotAfter < DateTime.UtcNow))
            errors.Add("All signing certificates have expired.");

        if (entity.Element(Ds + "Signature") is null)
            warnings.Add("Metadata is not signed. Confirm it came from your identity provider before activating.");

        return errors.Count > 0
            ? new SamlMetadataParseResult(null, errors)
            : new SamlMetadataParseResult(new SamlIdpMetadata(entityId!, ssoUrl, ssoBinding, certs, warnings), []);

        static SamlMetadataParseResult Fail(params string[] errs) => new(null, errs);
    }

    private static void CheckValidUntil(string? value, List<string> errors)
    {
        if (value is null) return;
        if (!DateTime.TryParse(value, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var validUntil))
            errors.Add("validUntil is not a valid date.");
        else if (validUntil < DateTime.UtcNow)
            errors.Add($"Metadata expired on {validUntil:yyyy-MM-dd HH:mm} UTC.");
    }
}
