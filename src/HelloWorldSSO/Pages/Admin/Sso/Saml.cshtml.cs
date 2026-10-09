using System.Security.Cryptography.X509Certificates;
using System.Text;
using HelloWorldSSO.Authentication;
using HelloWorldSSO.Models;
using HelloWorldSSO.Services;
using Microsoft.AspNetCore.Mvc;

namespace HelloWorldSSO.Pages.Admin.Sso;

[RequestSizeLimit(SamlMetadataParser.MaxMetadataBytes + 64 * 1024)]
public class SamlModel(SsoConfigurationService ssoConfigurations, IConfiguration configuration)
    : SsoConfigurationPageModel(ssoConfigurations, AuthenticationTypes.Saml)
{
    [BindProperty]
    public IFormFile? MetadataFile { get; set; }

    [BindProperty]
    public string? MetadataUrl { get; set; }

    public string SpEntityId => SamlAuthentication.SpEntityId(configuration);
    public string AcsUrl => SamlAuthentication.AcsUrl(configuration);
    public string SpMetadataUrl => SamlAuthentication.MetadataUrl(configuration);

    public IEnumerable<X509Certificate2> SigningCertificates =>
        (Config.SamlSigningCertificates ?? "")
        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(b64 => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(b64)));

    public async Task<IActionResult> OnPostValidateAsync(CancellationToken cancellationToken)
    {
        string? xml = null;
        if (MetadataFile is { Length: > 0 })
        {
            if (MetadataFile.Length > SamlMetadataParser.MaxMetadataBytes)
                return await AfterActionAsync(SsoOperationResult.Fail("Metadata exceeds the 1 MB size limit."), "");
            using var reader = new StreamReader(MetadataFile.OpenReadStream(), Encoding.UTF8);
            xml = await reader.ReadToEndAsync(cancellationToken);
        }

        var result = await SsoConfigurations.ImportSamlMetadataAsync(User.GetCustomerId(), Id, xml, MetadataUrl, cancellationToken);
        return await AfterActionAsync(result, "Metadata validated. Run a test sign-in next.");
    }
}
