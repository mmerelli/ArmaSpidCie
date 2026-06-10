using ArmaSpidCie.Configuration;
using ArmaSpidCie.Services;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using Microsoft.AspNetCore.Authentication.Cookies;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

// ─── Cookie Policy (necessario per SameSite=None cross-site SAML) ────────────
builder.Services.AddCookiePolicy(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.None;
    options.Secure = CookieSecurePolicy.Always;
});

// ─── Authentication + Cookie ──────────────────────────────────────────────────
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.LoginPath = "/Auth/Login";
});



// ─── Cache + Session ──────────────────────────────────────────────────────────────────
builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.IdleTimeout = TimeSpan.FromMinutes(10);
});

// ─── Configurazione provider ──────────────────────────────────────────────────
builder.Services.Configure<SpidConfig>(builder.Configuration.GetSection("Spid"));
builder.Services.Configure<CieConfig>(builder.Configuration.GetSection("Cie"));
 
// ─── ITfoxtec Saml2 ───────────────────────────────────────────────────────────
builder.Services.AddSaml2(slidingExpiration: true);

// ─── Provider SPID e CIE ─────────────────────────────────────────────────────
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IFederatedAuthProvider, SpidAuthProvider>();
builder.Services.AddScoped<IFederatedAuthProvider, CieAuthProvider>();

// ─── OpenAPI ──────────────────────────────────────────────────────────────────
builder.Services.AddOpenApi();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

// ─── Ordine middleware — l'ordine è fondamentale ──────────────────────────────
app.UseCookiePolicy();      // 1. prima di tutto
app.UseSession();           // 2. sessione
app.UseSaml2();             // 3. saml2
app.UseAuthentication();    // 4. autenticazione
app.UseAuthorization();     // 5. autorizzazione

app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
app.MapControllers();

app.Run();

 