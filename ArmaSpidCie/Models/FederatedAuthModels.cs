using System.Security.Claims;


namespace ArmaSpidCie.Models;

/// <summary>
/// Risultato dell'autenticazione, comune a SPID e CIE.
/// </summary>
public class FederatedAuthResult
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public FederatedUserInfo? User { get; set; }
    public string ReturnUrl { get; set; } = "/";
}

/// <summary>
/// Attributi utente estratti dalla SAML Response.
/// SPID ne restituisce di più; CIE si limita ai dati anagrafici.
/// </summary>
public class FederatedUserInfo
{
    // Comuni a SPID e CIE
    public string? CodiceFiscale { get; set; }
    public string? Nome { get; set; }
    public string? Cognome { get; set; }
    public string? DataNascita { get; set; }
    public string? LuogoNascita { get; set; }

    // Solo SPID
    public string? SpidCode { get; set; }
    public string? Email { get; set; }
    public string? Telefono { get; set; }
    public string? Indirizzo { get; set; }
    public string? Genere { get; set; }

    public string Provider { get; set; } = string.Empty;   // "SPID" o "CIE"
    public string AuthLevel { get; set; } = string.Empty;  // "SpidL2" o "Cie3"

    /// <summary>
    /// Converte gli attributi in ClaimsPrincipal per ASP.NET Core Identity.
    /// </summary>
    public ClaimsPrincipal ToClaimsPrincipal()
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name,           $"{Nome} {Cognome}"),
            new(ClaimTypes.GivenName,      Nome          ?? string.Empty),
            new(ClaimTypes.Surname,        Cognome       ?? string.Empty),
            new(ClaimTypes.DateOfBirth,    DataNascita   ?? string.Empty),
            new("fiscalNumber",            CodiceFiscale ?? string.Empty),
            new("authProvider",            Provider),
            new("authLevel",               AuthLevel),
        };

        if (!string.IsNullOrEmpty(SpidCode))
            claims.Add(new("spidCode", SpidCode));

        if (!string.IsNullOrEmpty(Email))
            claims.Add(new(ClaimTypes.Email, Email));

        if (!string.IsNullOrEmpty(Telefono))
            claims.Add(new(ClaimTypes.MobilePhone, Telefono));

        if (!string.IsNullOrEmpty(LuogoNascita))
            claims.Add(new("placeOfBirth", LuogoNascita));

        var identity = new ClaimsIdentity(claims, "FederatedAuth");
        return new ClaimsPrincipal(identity);
    }
}
