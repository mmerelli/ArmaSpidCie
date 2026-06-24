using ArmaSpidCie.Configuration;
using ArmaSpidCie.Models;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System.Security.Cryptography.X509Certificates;


namespace ArmaSpidCie.Services;

/// <summary>
/// Provider SPID — SAML 2.0, ITfoxtec.Identity.Saml2 v4.18.0
///
/// Pattern ACS corretto per la 4.x (da sample ufficiale):
///   1. var httpRequest = Request.ToGenericHttpRequest(validate: true)
///   2. httpRequest.Binding.ReadSamlResponse(httpRequest, samlResponse)  → deserializza
///   3. controlla samlResponse.Status
///   4. httpRequest.Binding.Unbind(httpRequest, samlResponse)            → valida firma
///   5. await samlResponse.CreateSessionAsync(HttpContext, ...)          → crea sessione
/// </summary>
public class SpidAuthProvider : IFederatedAuthProvider
{
    private readonly SpidConfig _config;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IMemoryCache _cache;

    public string ProviderName => "SPID";

    public SpidAuthProvider(IOptions<SpidConfig> config, IHttpContextAccessor httpContextAccessor, IMemoryCache cache)
    {
        _config = config.Value;
        _httpContextAccessor = httpContextAccessor;
        _cache = cache;
    }


    // ─── Login ────────────────────────────────────────────────────────────────
    public IActionResult StartLogin(string returnUrl, string? idpEntityId = null)
    {
        var idp = SetSelectedIdp(idpEntityId ?? "");

        // Verifica che l'IdP sia configurato correttamente
        if (idp is null)
            throw new InvalidOperationException("Nessun Identity Provider configurato.");

        if (string.IsNullOrEmpty(idp.SsoUrl))
            throw new InvalidOperationException($"SsoUrl non configurato per IdP: {idp.Name}");

        var samlConfig = BuildSamlConfig();

        // Verifica che SingleSignOnDestination sia valorizzato
        if (samlConfig.SingleSignOnDestination is null)
            throw new InvalidOperationException($"SingleSignOnDestination è null. SsoUrl: {idp.SsoUrl}");

        var binding = new Saml2RedirectBinding();

        binding.SetRelayStateQuery(new Dictionary<string, string>
        {
            { "ReturnUrl", returnUrl },
            { "IdP",       idp.EntityId }
        });

        return binding.Bind(new Saml2AuthnRequest(samlConfig)
        {
            RequestedAuthnContext = new RequestedAuthnContext
            {
                Comparison = AuthnContextComparisonTypes.Exact,
                AuthnContextClassRef = new[] { "https://www.spid.gov.it/SpidL2" }
            },
            NameIdPolicy = new NameIdPolicy
            {
                AllowCreate = false,
                Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
            },
            ForceAuthn = true,   // ← obbligatorio per SPID
            AttributeConsumingServiceIndex = 0,      // ← obbligatorio per SPID
            AssertionConsumerServiceIndex = 0,      // ← obbligatorio per SPID
            AssertionConsumerServiceUrl = new Uri(_config.AssertionConsumerServiceUrl)

        }).ToActionResult();
    }

    // ─── ACS ─────────────────────────────────────────────────────────────────
    public async Task<FederatedAuthResult> ProcessAcsResponse(HttpRequest request)
    {
        var samlConfig = BuildSamlConfig();
        var samlResponse = new Saml2AuthnResponse(samlConfig);

        try
        {
            // ✅ Pattern ufficiale 4.x
            var httpRequest = request.ToGenericHttpRequest(validate: true);

            // 1. Deserializza la risposta
            httpRequest.Binding.ReadSamlResponse(httpRequest, samlResponse);

            if (samlResponse.Status != Saml2StatusCodes.Success)
            {
                // Logga il messaggio esteso per capire la causa
                var statusMessage = samlResponse.StatusMessage ?? "nessun messaggio";
                //var statusDetail = samlResponse. ?? "nessun dettaglio";

                //_logger.LogWarning(
                //    "SPID errore — Status: {Status} | Message: {Message} | Detail: {Detail}",
                //    samlResponse.Status,
                //    statusMessage,
                //    statusDetail);

                return Fail($"SPID errore: {samlResponse.Status} — {statusMessage}");
            }

            //if (samlResponse.Status != Saml2StatusCodes.Success)
            //    return Fail($"SPID errore stato: {samlResponse.Status}");

            // 2. Valida firma e asserzioni
            httpRequest.Binding.Unbind(httpRequest, samlResponse);

            // 3. Crea la sessione ASP.NET Core (gestisce anche il cookie auth)
            await samlResponse.CreateSessionAsync(
                _httpContextAccessor.HttpContext!,
                claimsTransform: (claimsPrincipal) => Task.FromResult(claimsPrincipal));

            var claims = samlResponse.ClaimsIdentity;
            var relay = httpRequest.Binding.GetRelayStateQuery();

            var user = new FederatedUserInfo
            {
                Provider = "SPID",
                AuthLevel = "SpidL2",
                SpidCode = claims.FindFirst("spidCode")?.Value,
                CodiceFiscale = claims.FindFirst("fiscalNumber")?.Value,
                Nome = claims.FindFirst("name")?.Value,
                Cognome = claims.FindFirst("familyName")?.Value,
                DataNascita = claims.FindFirst("dateOfBirth")?.Value,
                LuogoNascita = claims.FindFirst("placeOfBirth")?.Value,
                Email = claims.FindFirst("email")?.Value,
                Telefono = claims.FindFirst("mobilePhone")?.Value,
                Indirizzo = claims.FindFirst("address")?.Value,
                Genere = claims.FindFirst("gender")?.Value,
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
            return Fail($"Errore validazione SPID: {ex.Message}");
        }
    }

    // ─── Logout ───────────────────────────────────────────────────────────────
    public IActionResult StartLogout(System.Security.Claims.ClaimsPrincipal user)
    {     
        var samlConfig = BuildSamlConfig();

        var binding = new Saml2RedirectBinding();

        // DeleteSession rimuove la sessione locale e prepara la LogoutRequest
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
                            xmlns:spid=""https://spid.gov.it/saml-extensions""
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

                            <md:AssertionConsumerService
                                Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
                                Location=""{_config.AssertionConsumerServiceUrl}""
                                index=""0""
                                isDefault=""true""/>

                            <md:AttributeConsumingService index=""0"">
                              <md:ServiceName xml:lang=""it"">MyApp</md:ServiceName>
                              <md:RequestedAttribute Name=""spidCode""     NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" isRequired=""true""/>
                              <md:RequestedAttribute Name=""fiscalNumber"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" isRequired=""true""/>
                              <md:RequestedAttribute Name=""name""         NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" isRequired=""true""/>
                              <md:RequestedAttribute Name=""familyName""   NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" isRequired=""true""/>
                              <md:RequestedAttribute Name=""dateOfBirth""  NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" isRequired=""true""/>
                              <md:RequestedAttribute Name=""email""        NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" isRequired=""false""/>
                            </md:AttributeConsumingService>

                          </md:SPSSODescriptor>

                          <!-- Obbligatorio per SPID -->
                          <md:Organization>
                            <md:OrganizationName xml:lang=""it"">MyOrg</md:OrganizationName>
                            <md:OrganizationDisplayName xml:lang=""it"">MyOrg</md:OrganizationDisplayName>
                            <md:OrganizationURL xml:lang=""it"">{_config.Issuer}</md:OrganizationURL>
                          </md:Organization>

                          <md:ContactPerson contactType=""other"">
                            <md:Extensions>
                              <spid:IPACode>IT12345678901</spid:IPACode>
                              <spid:Private/>
                            </md:Extensions>
                            <md:EmailAddress>admin@myorg.it</md:EmailAddress>
                          </md:ContactPerson>

                        </md:EntityDescriptor>";

        return new ContentResult
        {
            Content = xml,
            ContentType = "application/xml; charset=utf-8",
            StatusCode = 200
        };
    }


    public async Task<List<SpidIdPConfig>> GetSpidProviders()
    {
        string cacheKey = $"CACHE_PROVIDERS";

        if (!_cache.TryGetValue(cacheKey, out List<SpidIdPConfig>? datiInCache))
        {
            var client = new HttpClient();
            var response = await client.GetAsync("https://registry.spid.gov.it/entities-idp?output=json");

            if (!response.IsSuccessStatusCode)
                return [];

            var json = await response.Content.ReadAsStringAsync();
            var idps = ParseRegistryResponse(json);

            if (idps.Count == 0)
                return [];

            //---------------------------------------
            //Aggiungo demo per debug
            //---------------------------------------
            var idpsDemo = _config.IdentityProvidersDemo.ToList();
            foreach (var d in idpsDemo)
            {
                if (d != null)
                {
                    var s = new SpidIdPConfig
                    {
                        Name = d.Name,
                        EntityId = d.EntityId,
                        SsoUrl = d.SsoUrl,
                        SloUrl = d.SloUrl,
                        MetadataUrl = d.MetadataUrl,
                        LogoUrl = d.LogoUrl,
                        IdpCertificateBase64 = d.IdpCertificateBase64
                    };

                    idps.Insert(0, s);
                }
            }
            //---------------------------------------

            datiInCache = idps;

            var options = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(TimeSpan.FromHours(8));

            _cache.Set(cacheKey, datiInCache, options);
        }

        return datiInCache ?? [];
    }

    private List<SpidIdPConfig> ParseRegistryResponse(string json)
    {
        var result = new List<SpidIdPConfig>();


        var entries = System.Text.Json.JsonSerializer.Deserialize<List<AgIdIdpEntry>>(json,
            new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        if (entries is null) return result;

        foreach (var entry in entries)
        {
            // Prendi l'URL SSO con binding HTTP-Redirect (preferito per SPID)
            var ssoRedirect = entry.SingleSignOnService?
                .FirstOrDefault(s => s.Binding?.Contains("HTTP-Redirect") == true);

            var ssoPost = entry.SingleSignOnService?
                .FirstOrDefault(s => s.Binding?.Contains("HTTP-POST") == true);

            var ssoUrl = ssoRedirect?.Location ?? ssoPost?.Location;

            // Prendi l'URL SLO
            var sloUrl = entry.SingleLogoutService?
                .FirstOrDefault()?.Location;

            if (string.IsNullOrEmpty(entry.EntityId) ||
                string.IsNullOrEmpty(ssoUrl))
                continue;

            result.Add(new SpidIdPConfig
            {
                Name = entry.OrganizationName ?? entry.EntityId,
                EntityId = entry.EntityId,
                SsoUrl = ssoUrl,
                SloUrl = sloUrl ?? ssoUrl,
                MetadataUrl = $"{entry.EntityId}/metadata",
                LogoUrl = entry.LogoUri ?? string.Empty,
                IdpCertificateBase64 = entry.signing_certificate_x509.First()
            });
        }

        return result;
    }

    // ─── Helper ───────────────────────────────────────────────────────────────
    private Saml2Configuration BuildSamlConfig() 
    {        
        var cert = CertificateHelper.Get(_config);

        var cfg = new Saml2Configuration
        {
            Issuer = _config.Issuer,
            SigningCertificate = cert,
            SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            CertificateValidationMode =
                System.ServiceModel.Security.X509CertificateValidationMode.None,
            RevocationMode =
                System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
            AudienceRestricted = true,
        };

        cfg.AllowedAudienceUris.Add(_config.Issuer);


        SpidIdPConfig spidIdPConfig = GetSelectedIdp();

        // Assegna esplicitamente con controllo
        if (!string.IsNullOrWhiteSpace(spidIdPConfig.SsoUrl))
            cfg.SingleSignOnDestination = new Uri(spidIdPConfig.SsoUrl, UriKind.Absolute);

        if (!string.IsNullOrWhiteSpace(spidIdPConfig.SloUrl))
            cfg.SingleLogoutDestination = new Uri(spidIdPConfig.SloUrl, UriKind.Absolute);

        // Certificato IdP
        if (!string.IsNullOrEmpty(spidIdPConfig.IdpCertificateBase64))
        {
            var certBytes = Convert.FromBase64String(spidIdPConfig.IdpCertificateBase64);
            var idpCert = X509CertificateLoader.LoadCertificate(certBytes);
            cfg.SignatureValidationCertificates.Add(idpCert);
        }

        return cfg;
    }

    private static FederatedAuthResult Fail(string message) =>
        new() { Success = false, ErrorMessage = message };


    private SpidIdPConfig SetSelectedIdp(string entityId)
    {
        var providers = GetSpidProviders().GetAwaiter().GetResult();
        var idp = providers.FirstOrDefault(t => t.EntityId == entityId);

        var idpJson = JsonConvert.SerializeObject(idp);

        _httpContextAccessor.HttpContext!.Session.Remove("spid_idp");
        _httpContextAccessor.HttpContext!.Session.SetString("spid_idp", idpJson);

        return idp ?? new();
    }

    private SpidIdPConfig GetSelectedIdp()
    {
        var idpJson = _httpContextAccessor.HttpContext!.Session.GetString("spid_idp") ?? "";
        var idp = JsonConvert.DeserializeObject<SpidIdPConfig>(idpJson);
        return idp ?? new();
    }
}