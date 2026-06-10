# SpidCieAuth — Implementazione SPID + CIE in C# / ASP.NET Core

Implementazione unificata di **SPID** e **CIE** tramite SAML 2.0,
con un unico controller e due provider intercambiabili.

---

## Struttura del progetto

```
SpidCieAuth/
├── Configuration/
│   └── AuthProviderConfig.cs      # SpidConfig, CieConfig, SpidIdPConfig
├── Models/
│   └── FederatedAuthModels.cs     # FederatedAuthResult, FederatedUserInfo
├── Services/
│   ├── IFederatedAuthProvider.cs  # Interfaccia comune SPID/CIE
│   ├── SpidAuthProvider.cs        # Logica SAML per SPID
│   └── CieAuthProvider.cs         # Logica SAML per CIE
├── Controllers/
│   └── FederatedAuthController.cs # Controller unico, route /auth/{provider}/*
├── Program.cs                     # DI, cookie auth
└── appsettings.json               # Configurazione IdP e certificati
```

---

## Route esposte

| Route | Metodo | Descrizione |
|---|---|---|
| `/auth/spid/login?idp={entityId}` | GET | Avvia login SPID (redirect binding) |
| `/auth/cie/login` | GET | Avvia login CIE (POST binding) |
| `/auth/spid/acs` | POST | Riceve SAMLResponse SPID |
| `/auth/cie/acs` | POST | Riceve SAMLResponse CIE |
| `/auth/spid/logout` | GET | Single Logout SPID |
| `/auth/cie/logout` | GET | Single Logout CIE |
| `/auth/spid/metadata` | GET | Metadata SP per SPID |
| `/auth/cie/metadata` | GET | Metadata SP per CIE |

---

## Riepilogo differenze SPID vs CIE nel codice

| Aspetto | SPID | CIE |
|---|---|---|
| **Binding login** | `Saml2RedirectBinding` | `Saml2PostBinding` |
| **Binding logout** | Redirect | POST |
| **AuthnContext** | `https://www.spid.gov.it/SpidL2` | `https://www.cartaidentita.interno.gov.it/identification/Cie3` |
| **Comparison** | `Exact` | `Minimum` |
| **ForceAuthn** | `false` | `true` |
| **IdP** | Multipli (Poste, INPS, Aruba…) | Uno solo (Ministero Interno) |
| **Attributi** | Set esteso (email, tel, indirizzo…) | Solo dati anagrafici ANPR |

---

## Installazione pacchetti NuGet

```bash
dotnet add package ITfoxtec.Identity.Saml2
dotnet add package ITfoxtec.Identity.Saml2.MvcCore
```

---

## Generare il certificato SP (sviluppo)

```bash
openssl req -x509 -newkey rsa:2048 -keyout sp-key.pem \
  -out sp-cert.pem -days 365 -nodes \
  -subj "/CN=tuoapp.it/O=MyOrg/C=IT"

openssl pkcs12 -export -out sp-cert.pfx \
  -inkey sp-key.pem -in sp-cert.pem \
  -passout pass:cambia-questa-password
```

Copia il file `.pfx` in `Certificates/`.

---

## IdP di test (sviluppo)

- **SPID**: https://demo.spid.gov.it — IdP di test AgID
- **CIE**: https://collaudo.idserver.servizicie.interno.gov.it — ambiente di collaudo
- **Validator**: https://validator.spid.gov.it — valida metadata e richieste

---

## Percorso verso la produzione

1. Generare un certificato X.509 qualificato
2. Registrarsi come SP su **agid.gov.it** (SPID) e **cartaidentita.interno.gov.it** (CIE)
3. Superare i test con lo SPID Validator / CIE Validator
4. Ricevere l'accreditamento e aggiornare gli URL in `appsettings.json`
