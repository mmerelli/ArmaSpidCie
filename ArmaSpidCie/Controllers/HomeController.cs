using ArmaSpidCie.Configuration;
using ArmaSpidCie.Services;
using Microsoft.AspNetCore.Mvc;

namespace ArmaSpidCie.Controllers
{
    public class HomeController : Controller
    {
        private readonly IEnumerable<IFederatedAuthProvider> _providers;

        public HomeController(IEnumerable<IFederatedAuthProvider> providers)
        {
            _providers = providers;
        }

        private IFederatedAuthProvider? Resolve(string provider) 
            => _providers.FirstOrDefault(p => p.ProviderName.Equals(provider, StringComparison.OrdinalIgnoreCase));

        public async Task<IActionResult> Index(string returnUrl = "/")
        {            
            var spidProvider = Resolve("spid") as SpidAuthProvider;
            if (spidProvider is null) return NotFound($"Provider 'spid' non supportato.");

            var _providers  = await spidProvider.GetSpidProviders();

            // Usa la lista aggiornata dal registro AgID               
            ViewBag.SpidProviders = _providers;
            ViewBag.ReturnUrl = returnUrl;

            return View();                                              
        }
    }
}
 
 