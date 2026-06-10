using ArmaSpidCie.Configuration;
using ArmaSpidCie.Models;
using ArmaSpidCie.Services;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Cryptography.X509Certificates;

namespace ArmaSpidCie.Services;

/// <summary>
/// Provider CIE — SAML 2.0, ITfoxtec.Identity.Saml2 v4.18.0
///
/// Stesso pattern ACS di SPID, differenze:
///   - Binding: SOLO POST (login, logout, ACS)
///   - AuthnContext: namespace CIE, Comparison = Minimum
///   - ForceAuthn = true
///   - Attributi: solo dati anagrafici ANPR
/// </summary>
public class CieAuthProvider : IFederatedAuthProvider
{
    private readonly CieConfig _config;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public string ProviderName => "CIE";

    public CieAuthProvider(
        IOptions<CieConfig> config,
        IHttpContextAccessor httpContextAccessor)
    {
        _config = config.Value;
        _httpContextAccessor = httpContextAccessor;
    }

    // ─── Login ────────────────────────────────────────────────────────────────

    public IActionResult StartLogin(string returnUrl, string? idpEntityId = null)
    {
        var samlConfig = BuildSamlConfig();

        // ✅ CIE richiede REDIRECT binding per la AuthnRequest  
        var binding = new Saml2RedirectBinding();

        binding.SetRelayStateQuery(new Dictionary<string, string>
        {
            { "ReturnUrl", returnUrl }
        });

        return binding.Bind(new Saml2AuthnRequest(samlConfig)
        {
            ForceAuthn = true,
            NameIdPolicy = new NameIdPolicy
            {
                AllowCreate = true,
                Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
            },
            RequestedAuthnContext = new RequestedAuthnContext
            {
                Comparison = AuthnContextComparisonTypes.Minimum,
                AuthnContextClassRef = new[]
                {
                "https://www.cie.gov.it/cie/Cie1"
            }
            }
        }).ToActionResult();
    }

    // ─── ACS ─────────────────────────────────────────────────────────────────

    public async Task<FederatedAuthResult> ProcessAcsResponse(HttpRequest request)
    {
        var samlConfig = BuildSamlConfig();
        var samlResponse = new Saml2AuthnResponse(samlConfig);

        try
        {
            // ✅ Pattern ufficiale 4.x — identico a SPID, cambia solo la config
            var httpRequest = request.ToGenericHttpRequest(validate: true);

            httpRequest.Binding.ReadSamlResponse(httpRequest, samlResponse);

            if (samlResponse.Status != Saml2StatusCodes.Success)
                return Fail($"CIE errore stato: {samlResponse.Status}");

            httpRequest.Binding.Unbind(httpRequest, samlResponse);

            await samlResponse.CreateSessionAsync(
                _httpContextAccessor.HttpContext!,
                claimsTransform: (claimsPrincipal) => Task.FromResult(claimsPrincipal));

            var claims = samlResponse.ClaimsIdentity;
            var relay = httpRequest.Binding.GetRelayStateQuery();

            // ▸ CIE: solo attributi anagrafici, email/tel/indirizzo non disponibili
            var user = new FederatedUserInfo
            {
                Provider = "CIE",
                AuthLevel = "Cie3",
                CodiceFiscale = claims.FindFirst("fiscalNumber")?.Value,
                Nome = claims.FindFirst("name")?.Value,
                Cognome = claims.FindFirst("familyName")?.Value,
                DataNascita = claims.FindFirst("dateOfBirth")?.Value,
                LuogoNascita = claims.FindFirst("placeOfBirth")?.Value,
                Email = null,
                Telefono = null,
                Genere = null,
            };

            return new FederatedAuthResult
            {
                Success = true,
                User = user,
                ReturnUrl = relay.TryGetValue("ReturnUrl", out var url) ? url : "/"
            };
        }
        catch (Exception ex)
        {
            return Fail($"Errore validazione CIE: {ex.Message}");
        }
    }

    // ─── Logout ───────────────────────────────────────────────────────────────

    public IActionResult StartLogout(System.Security.Claims.ClaimsPrincipal user)
    {
        var samlConfig = BuildSamlConfig();

        // ▸ CIE: anche logout usa POST
        var binding = new Saml2PostBinding();
        var logoutRequest = new Saml2LogoutRequest(samlConfig, user);

        return binding.Bind(logoutRequest).ToActionResult();
    }

    // Callback SLO ricevuta dall'IdP
    public IActionResult HandleSloCallback(HttpRequest request)
    {
        var samlConfig = BuildSamlConfig();
        var httpRequest = request.ToGenericHttpRequest(validate: true);
        httpRequest.Binding.Unbind(httpRequest, new Saml2LogoutResponse(samlConfig));
        return new RedirectResult("/");
    }

    // ─── Metadata SP ─────────────────────────────────────────────────────────


    public ContentResult GetMetadata()
    {
        var samlConfig = BuildSamlConfig();

        var certBase64 = Convert.ToBase64String(samlConfig.SigningCertificate.RawData);

        var xml = $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<md:EntityDescriptor
    xmlns:md=""urn:oasis:names:tc:SAML:2.0:metadata""
    xmlns:ds=""http://www.w3.org/2000/09/xmldsig#""
    entityID=""{_config.Issuer}"">

  <md:SPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol""
      AuthnRequestsSigned=""true""
      WantAssertionsSigned=""true"">

    <md:KeyDescriptor use=""signing"">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{certBase64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>

    <!-- CIE: solo POST binding sull'ACS -->
    <md:AssertionConsumerService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
        Location=""{_config.AssertionConsumerServiceUrl}""
        index=""0""
        isDefault=""true""/>

    <!-- CIE: solo attributi disponibili su ANPR -->
    <md:AttributeConsumingService index=""0"">
      <md:ServiceName xml:lang=""it"">MyApp</md:ServiceName>
      <md:RequestedAttribute Name=""fiscalNumber"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" isRequired=""true""/>
      <md:RequestedAttribute Name=""name""         NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" isRequired=""true""/>
      <md:RequestedAttribute Name=""familyName""   NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" isRequired=""true""/>
      <md:RequestedAttribute Name=""dateOfBirth""  NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" isRequired=""true""/>
    </md:AttributeConsumingService>

  </md:SPSSODescriptor>

</md:EntityDescriptor>";

        return new ContentResult
        {
            Content = xml,
            ContentType = "application/xml; charset=utf-8",
            StatusCode = 200
        };
    }

    //public ContentResult GetMetadata()
    //{
    //    var samlConfig = BuildSamlConfig();

    //    var entityDescriptor = new EntityDescriptor(samlConfig)
    //    {
    //        ValidUntil = 365,
    //        SPSsoDescriptor = new SPSsoDescriptor
    //        {
    //            AuthnRequestsSigned = true,
    //            WantAssertionsSigned = true,
    //            SigningCertificates = new[] { samlConfig.SigningCertificate },
    //            AssertionConsumerServices = new[]
    //            {
    //                new AssertionConsumerService
    //                {
    //                    // ▸ CIE: solo POST sull'ACS
    //                    Binding   = ProtocolBindings.HttpPost,
    //                    Location  = new Uri(_config.AssertionConsumerServiceUrl),
    //                    IsDefault = true,
    //                    Index     = 0
    //                }
    //            },
    //            AttributeConsumingServices = new[]
    //            {
    //                new AttributeConsumingService
    //                {
    //                    ServiceNames = new[] { new LocalizedNameType("MyApp", "it") },
    //                    RequestedAttributes = new[]
    //                    {
    //                        new RequestedAttribute("fiscalNumber"),
    //                        new RequestedAttribute("name"),
    //                        new RequestedAttribute("familyName"),
    //                        new RequestedAttribute("dateOfBirth"),
    //                    }
    //                }
    //            }
    //        }
    //    };

    //    return new Saml2Metadata(entityDescriptor)
    //        .CreateMetadata()
    //        .ToActionResult() as ContentResult
    //        ?? new ContentResult { ContentType = "application/xml", StatusCode = 200 };
    //}

    // ─── Helper ───────────────────────────────────────────────────────────────

    private Saml2Configuration BuildSamlConfig()
    {
        var certPath = Path.Combine(AppContext.BaseDirectory, _config.CertificatePath);
        var cert = X509CertificateLoader.LoadPkcs12FromFile(
                certPath,
                _config.CertificatePassword,
                X509KeyStorageFlags.MachineKeySet);

        var cfg = new Saml2Configuration
        {
            Issuer = _config.Issuer,
            SingleSignOnDestination = new Uri(_config.SsoUrl),
            SingleLogoutDestination = new Uri(_config.SloUrl),
            SigningCertificate = cert,
            SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            SignAuthnRequest = true,    

            CertificateValidationMode =
            System.ServiceModel.Security.X509CertificateValidationMode.None,
            RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,

            AudienceRestricted = true,
        };
         
        cfg.AllowedAudienceUris.Add(_config.Issuer);

        // Certificato IdP
        if (!string.IsNullOrEmpty(_config.IdpCertificateBase64))
        {
            var certBytes = Convert.FromBase64String(_config.IdpCertificateBase64);
            var idpCert = X509CertificateLoader.LoadCertificate(certBytes);
            cfg.SignatureValidationCertificates.Add(idpCert);
        }
 
        return cfg;
    }
     
    private static FederatedAuthResult Fail(string message) =>
        new() { Success = false, ErrorMessage = message };
}