using ArmaSpidCie.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace ArmaSpidCie.Services;

public static class CertificateHelper
{
    /// <summary>
    /// Recupera il certificato in base alla configurazione fornita. 
    /// Se è specificato un thumbprint, recupera il certificato dallo store di Windows; 
    /// altrimenti, recupera il certificato da un file .pfx.
    /// </summary>
    /// <param name="spidConfig"></param>
    /// <returns></returns>
    public static X509Certificate2 Get(SpidConfig spidConfig)
    {            
        if (string.IsNullOrWhiteSpace(spidConfig.CertificateThumbprint))            
            return GetByPath(spidConfig.CertificatePath, spidConfig.CertificatePassword);            
        else            
            return GetByThumbPrint(spidConfig.CertificateThumbprint);            
    }

    /// <summary>
    /// Recupera il certificato in base alla configurazione fornita. 
    /// Se è specificato un thumbprint, recupera il certificato dallo store di Windows; 
    /// altrimenti, recupera il certificato da un file .pfx.
    /// </summary>
    /// <param name="cieConfig"></param>
    /// <returns></returns>
    public static X509Certificate2 Get(CieConfig cieConfig)
    {
        if (string.IsNullOrWhiteSpace(cieConfig.CertificateThumbprint))
            return GetByPath(cieConfig.CertificatePath, cieConfig.CertificatePassword);
        else
            return GetByThumbPrint(cieConfig.CertificateThumbprint);
    }

    /// <summary>
    /// Recupero il certificato da file .pfx 
    /// (usato principalmente in sviluppo o per test locali, ma non è consigliato in produzione).
    /// </summary>
    /// <param name="path"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    private static X509Certificate2 GetByPath(string path, string password)
    {
        var certPath = Path.Combine(AppContext.BaseDirectory, path);
        
        var cert = X509CertificateLoader.LoadPkcs12FromFile(certPath,password,X509KeyStorageFlags.MachineKeySet);

        return cert;
    }

    /// <summary>
    /// Recupero il certificato dallo store di Windows usando il thumbprint 
    /// (usato principalmente in produzione, con certificati installati tramite MMC o script di deployment).
    /// </summary>
    /// <param name=""></param>
    /// <returns></returns>
    private static X509Certificate2 GetByThumbPrint(string thumbprint)
    {           
        //Spesso il thumbprint copiato  contiene spazi o caratteri invisibili. E' necessario normalizzarlo.
        thumbprint = Regex.Replace(thumbprint,@"[^\da-fA-F]",string.Empty).ToUpperInvariant();

        using var store = new X509Store(StoreName.My,StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        var certs = store.Certificates.Find(X509FindType.FindByThumbprint,thumbprint,false);

        return certs.Count > 0 ? certs[0] : 
                throw new InvalidOperationException("Certificato non trovato");
    }
}

