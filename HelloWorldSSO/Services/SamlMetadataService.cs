using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace HelloWorldSSO.Services;

public record SamlIdpInfo(string EntityId, string SingleSignOnUrl, bool UsesPostBinding, IReadOnlyList<string> SigningCertificates);

public class SamlMetadataException(string message) : Exception(message);

public static class SamlMetadataParser
{
    public const int MaxMetadataBytes = 1_000_000;
    private static readonly XNamespace Md = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static readonly XNamespace Ds = "http://www.w3.org/2000/09/xmldsig#";
    private const string RedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    private const string PostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    public static SamlIdpInfo Parse(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml) || xml.Length > MaxMetadataBytes)
            throw new SamlMetadataException("Metadata is empty or too large.");

        XDocument doc;
        try
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersFromEntities = 0 };
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            doc = XDocument.Load(reader);
        }
        catch (XmlException)
        {
            throw new SamlMetadataException("Metadata is not valid XML.");
        }

        var root = doc.Root ?? throw new SamlMetadataException("Metadata is empty.");
        XElement entity;
        if (root.Name == Md + "EntityDescriptor") entity = root;
        else if (root.Name == Md + "EntitiesDescriptor" && root.Elements(Md + "EntityDescriptor").Count() == 1)
            entity = root.Element(Md + "EntityDescriptor")!;
        else throw new SamlMetadataException("Metadata must contain exactly one SAML EntityDescriptor.");

        var entityId = (string?)entity.Attribute("entityID");
        if (string.IsNullOrWhiteSpace(entityId) || entityId.Length > 512)
            throw new SamlMetadataException("Metadata has no valid entityID.");

        var idp = entity.Element(Md + "IDPSSODescriptor")
            ?? throw new SamlMetadataException("Metadata has no IDPSSODescriptor.");

        var services = idp.Elements(Md + "SingleSignOnService")
            .Select(e => (Binding: (string?)e.Attribute("Binding"), Location: (string?)e.Attribute("Location")))
            .Where(s => s.Location is not null && (s.Binding == RedirectBinding || s.Binding == PostBinding))
            .ToList();
        var sso = services.FirstOrDefault(s => s.Binding == RedirectBinding);
        if (sso.Location is null) sso = services.FirstOrDefault();
        if (sso.Location is null)
            throw new SamlMetadataException("Metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService.");
        if (!Uri.TryCreate(sso.Location, UriKind.Absolute, out var ssoUri) || ssoUri.Scheme != Uri.UriSchemeHttps)
            throw new SamlMetadataException("The SingleSignOnService location must be an absolute https URL.");

        var certs = new List<string>();
        foreach (var kd in idp.Elements(Md + "KeyDescriptor"))
        {
            var use = (string?)kd.Attribute("use");
            if (use is not null && use != "signing") continue;
            foreach (var c in kd.Descendants(Ds + "X509Certificate"))
            {
                try
                {
                    using var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(c.Value.Trim()));
                    if (cert.NotAfter.ToUniversalTime() > DateTime.UtcNow) certs.Add(Convert.ToBase64String(cert.RawData));
                }
                catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException)
                {
                    throw new SamlMetadataException("Metadata contains an invalid signing certificate.");
                }
            }
        }
        if (certs.Count == 0)
            throw new SamlMetadataException("Metadata contains no valid (unexpired) signing certificate.");

        return new SamlIdpInfo(entityId.Trim(), ssoUri.ToString(), sso.Binding == PostBinding, certs);
    }
}

/// <summary>Fetches IdP metadata over HTTPS only, refusing private/loopback/link-local targets (SSRF protection).</summary>
public class SafeMetadataFetcher(IHttpClientFactory factory)
{
    public const string ClientName = "saml-metadata";

    public async Task<string> FetchAsync(string url, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(uri.UserInfo))
            throw new SamlMetadataException("Metadata URL must be an absolute https URL.");
        if (IPAddress.TryParse(uri.Host, out var literal) && IsBlocked(literal))
            throw new SamlMetadataException("Metadata URL points to a disallowed address.");

        try
        {
            using var client = factory.CreateClient(ClientName);
            using var resp = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!resp.IsSuccessStatusCode)
                throw new SamlMetadataException($"Metadata URL returned HTTP {(int)resp.StatusCode}.");
            if (resp.Content.Headers.ContentLength > SamlMetadataParser.MaxMetadataBytes)
                throw new SamlMetadataException("Metadata is too large.");
            await using var stream = await resp.Content.ReadAsStreamAsync(ct);
            var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int n;
            while ((n = await stream.ReadAsync(chunk, ct)) > 0)
            {
                buffer.Write(chunk, 0, n);
                if (buffer.Length > SamlMetadataParser.MaxMetadataBytes)
                    throw new SamlMetadataException("Metadata is too large.");
            }
            return System.Text.Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new SamlMetadataException("Could not retrieve metadata from the URL.");
        }
    }

    /// <summary>Connect callback: resolves DNS and connects only to public addresses (also defeats DNS rebinding).</summary>
    public static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext ctx, CancellationToken ct)
    {
        var addresses = await Dns.GetHostAddressesAsync(ctx.DnsEndPoint.Host, ct);
        var allowed = addresses.Where(a => !IsBlocked(a)).ToArray();
        if (allowed.Length == 0 || allowed.Length != addresses.Length)
            throw new HttpRequestException("Destination address is not allowed.");
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(allowed, ctx.DnsEndPoint.Port, ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public static bool IsBlocked(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var v6 = ip.GetAddressBytes();
            // NAT64 (64:ff9b::/96) embeds an IPv4 address; evaluate that address instead.
            if (v6[0] == 0 && v6[1] == 0x64 && v6[2] == 0xff && v6[3] == 0x9b && v6[4..12].All(x => x == 0))
                return IsBlocked(new IPAddress(v6[12..16]));
        }
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || ip.IsIPv6UniqueLocal;
        var b = ip.GetAddressBytes();
        return b[0] == 10 || b[0] == 0 || b[0] >= 224
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254)
            || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
            || (b[0] == 192 && b[1] == 0 && b[2] is 0 or 2)
            || (b[0] == 198 && (b[1] is 18 or 19 || (b[1] == 51 && b[2] == 100)))
            || (b[0] == 203 && b[1] == 0 && b[2] == 113);
    }
}
