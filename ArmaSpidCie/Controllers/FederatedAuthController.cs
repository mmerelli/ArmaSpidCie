using ArmaSpidCie.Configuration;
using ArmaSpidCie.Models;
using ArmaSpidCie.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace ArmaSpidCie.Controllers;

/// <summary>
/// Controller unico per SPID e CIE.
/// Route: /auth/{provider}/...   (provider = "spid" | "cie")
///
/// NOTA: CreateSessionAsync (chiamata nei provider) gestisce il cookie di autenticazione
/// direttamente tramite HttpContext — il controller non chiama SignInAsync separatamente.
/// </summary>
[ApiController]
[Route("auth/{provider}")]
public class FederatedAuthController : Controller
{
    private readonly IEnumerable<IFederatedAuthProvider> _providers;
    private readonly ILogger<FederatedAuthController> _logger;
    private readonly SpidConfig _spidConfig;
    
    public FederatedAuthController(
        IEnumerable<IFederatedAuthProvider> providers,
        ILogger<FederatedAuthController> logger,
        IOptions<SpidConfig> spidConfig)
    {
        _providers = providers;
        _logger = logger;
        _spidConfig = spidConfig.Value;        
    }

    private IFederatedAuthProvider? Resolve(string provider) =>
        _providers.FirstOrDefault(p =>
            p.ProviderName.Equals(provider, StringComparison.OrdinalIgnoreCase));


    [AllowAnonymous]
    [HttpGet("providers")]
    public async Task<IActionResult> Providers(string provider, string returnUrl = "/")
    {
        var spidProvider = Resolve("spid") as SpidAuthProvider;
        if (spidProvider is null) return NotFound($"Provider '{provider}' non supportato.");

        return Ok(await spidProvider.GetSpidProviders());            
    }    

    // ─── Login ────────────────────────────────────────────────────────────────

    /// GET /auth/spid/login?idp=https://posteid.poste.it&returnUrl=/dashboard
    /// GET /auth/cie/login?returnUrl=/dashboard
    [AllowAnonymous]
    [HttpGet("login")]
    public IActionResult Login(string provider, string returnUrl = "/", string? idp = null)
    {
        var authProvider = Resolve(provider);
        if (authProvider is null) return NotFound($"Provider '{provider}' non supportato.");

        _logger.LogInformation("Login {Provider} → IdP: {IdP}", provider, idp ?? "default");
        return authProvider.StartLogin(returnUrl, idp);
    }

    // ─── ACS ─────────────────────────────────────────────────────────────────

    /// POST /auth/spid/acs
    /// POST /auth/cie/acs
    [AllowAnonymous]
    [HttpPost("acs")]
    public async Task<IActionResult> AssertionConsumerService(string provider)
    {
        var authProvider = Resolve(provider);
        if (authProvider is null) return NotFound();

        var result = await authProvider.ProcessAcsResponse(Request);

        if (!result.Success)
        {
            _logger.LogWarning("ACS {Provider} fallito: {Error}", provider, result.ErrorMessage);
            return RedirectToAction("Error", "Home", new { message = result.ErrorMessage });
        }

        _logger.LogInformation(
            "Login {Provider} OK — CF: {CF}",
            provider,
            result.User?.CodiceFiscale ?? "n/d");

        // CreateSessionAsync ha già fatto il SignIn tramite HttpContext
        // quindi redirect diretto all'URL di destinazione
        return LocalRedirect(result.ReturnUrl);
    }

    // ─── Logout ───────────────────────────────────────────────────────────────

    /// GET /auth/spid/logout
    /// GET /auth/cie/logout
    [Authorize]
    [HttpGet("logout")]
    public IActionResult Logout(string provider)
    {
        var authProvider = Resolve(provider);
        if (authProvider is null) return RedirectToAction("Index", "Home");

        return authProvider.StartLogout(User);
    }

    /// POST+GET /auth/spid/slo-callback
    /// POST+GET /auth/cie/slo-callback
    [AllowAnonymous]
    [HttpGet("slo-callback")]
    [HttpPost("slo-callback")]
    public IActionResult SloCallback(string provider)
    {
        var authProvider = Resolve(provider);
        if (authProvider is null) return RedirectToAction("Index", "Home");

        _logger.LogInformation("SLO completato per {Provider}", provider);
        return authProvider.HandleSloCallback(Request);
    }

    // ─── Metadata ─────────────────────────────────────────────────────────────

    /// GET /auth/spid/metadata
    /// GET /auth/cie/metadata
    [AllowAnonymous]
    [HttpGet("metadata")]
    [Produces("application/xml")]
    public IActionResult Metadata(string provider)
    {
        var authProvider = Resolve(provider);
        if (authProvider is null) return NotFound();

        return authProvider.GetMetadata();
    }

    [Authorize]
    [HttpGet("Profile")]
    public IActionResult Profile()
    {
        var claims = User.Claims.Select(c => new { c.Type, c.Value });
        return Ok(claims);
    }
}