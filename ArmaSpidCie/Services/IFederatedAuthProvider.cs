using ArmaSpidCie.Models;
using Microsoft.AspNetCore.Mvc;

namespace ArmaSpidCie.Services;

public interface IFederatedAuthProvider
{
    string ProviderName { get; }

    IActionResult StartLogin(string returnUrl, string? idpEntityId = null);

    Task<FederatedAuthResult> ProcessAcsResponse(HttpRequest request);

    IActionResult StartLogout(System.Security.Claims.ClaimsPrincipal user);

    // Gestisce il callback SLO ricevuto dall'IdP dopo il logout
    IActionResult HandleSloCallback(HttpRequest request);

    ContentResult GetMetadata();
}