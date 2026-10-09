using System.Net;
using System.Net.Sockets;
using System.Text;

namespace HelloWorldSSO.Services;

/// <summary>
/// Fetches customer-supplied metadata URLs with server-side request forgery protections:
/// HTTPS on port 443 only, no redirects, a short timeout, a response size cap, and a connect
/// callback that refuses private, loopback, link-local and other non-public addresses. The
/// check happens on the resolved address actually being connected to, so DNS rebinding cannot
/// bypass it.
/// </summary>
public class SafeMetadataFetcher
{
    public const string HttpClientName = "SafeMetadataFetcher";

    private readonly IHttpClientFactory _httpClientFactory;

    public SafeMetadataFetcher(IHttpClientFactory httpClientFactory) => _httpClientFactory = httpClientFactory;

    public static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
        ConnectTimeout = TimeSpan.FromSeconds(5),
        ConnectCallback = async (context, cancellationToken) =>
        {
            var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken);
            var allowed = addresses.Where(IsPublicAddress).ToArray();
            if (allowed.Length == 0 || allowed.Length != addresses.Length)
                throw new HttpRequestException("The metadata host resolves to a non-public address.");

            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(allowed, context.DnsEndPoint.Port, cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        },
    };

    public async Task<(string? Xml, string? Error)> FetchAsync(string url, CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return (null, "Metadata URL is not a valid absolute URL.");
        if (uri.Scheme != Uri.UriSchemeHttps)
            return (null, "Metadata URL must use HTTPS.");
        if (!uri.IsDefaultPort)
            return (null, "Metadata URL must use the default HTTPS port (443).");
        if (!string.IsNullOrEmpty(uri.UserInfo))
            return (null, "Metadata URL must not contain credentials.");
        if (IPAddress.TryParse(uri.IdnHost, out _))
            return (null, "Metadata URL must use a host name, not an IP address.");

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10));

            var client = _httpClientFactory.CreateClient(HttpClientName);
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Accept.ParseAdd("application/samlmetadata+xml, application/xml, text/xml");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);

            if ((int)response.StatusCode is >= 300 and < 400)
                return (null, "Metadata URL redirected; enter the final URL instead.");
            if (!response.IsSuccessStatusCode)
                return (null, $"Metadata URL returned HTTP {(int)response.StatusCode}.");
            if (response.Content.Headers.ContentLength > SamlMetadataParser.MaxMetadataBytes)
                return (null, "Metadata exceeds the 1 MB size limit.");

            await using var stream = await response.Content.ReadAsStreamAsync(cts.Token);
            var buffer = new MemoryStream();
            var chunk = new byte[16 * 1024];
            int read;
            while ((read = await stream.ReadAsync(chunk, cts.Token)) > 0)
            {
                buffer.Write(chunk, 0, read);
                if (buffer.Length > SamlMetadataParser.MaxMetadataBytes)
                    return (null, "Metadata exceeds the 1 MB size limit.");
            }
            return (Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length), null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return (null, "Timed out fetching the metadata URL.");
        }
        catch (HttpRequestException ex)
        {
            return (null, $"Could not fetch the metadata URL: {ex.Message}");
        }
    }

    public static bool IsPublicAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            return false;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] == 0
                || b[0] == 10
                || b[0] == 127
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)   // carrier-grade NAT
                || (b[0] == 169 && b[1] == 254)                  // link-local, incl. cloud metadata endpoints
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 0 && b[2] == 0)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 198 && (b[1] == 18 || b[1] == 19))  // benchmarking
                || b[0] >= 224);                                  // multicast and reserved
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = address.GetAddressBytes();
            return !(address.IsIPv6LinkLocal
                || address.IsIPv6SiteLocal
                || address.IsIPv6Multicast
                || address.IsIPv6UniqueLocal
                || (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)); // documentation
        }

        return false;
    }
}
