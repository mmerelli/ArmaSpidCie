namespace ArmaSpidCie.Configuration;

public class SpidConfig
{
    public string Issuer { get; set; } = string.Empty;
    public string AssertionConsumerServiceUrl { get; set; } = string.Empty;
    public string SingleLogoutUrl { get; set; } = string.Empty;
    public string CertificatePath { get; set; } = string.Empty;
    public string CertificatePassword { get; set; } = string.Empty;

    // Lista degli Identity Provider SPID Demo disponibili
    public List<SpidIdPConfig> IdentityProvidersDemo { get; set; } = new();    
}

public class SpidIdPConfig
{
    public string Name { get; set; } = string.Empty;           // es. "Poste Italiane"
    public string EntityId { get; set; } = string.Empty;       // es. "https://posteid.poste.it"
    public string SsoUrl { get; set; } = string.Empty;
    public string SloUrl { get; set; } = string.Empty;
    public string MetadataUrl { get; set; } = string.Empty;
    public string LogoUrl { get; set; } = string.Empty;
    public string IdpCertificateBase64 { get; set; } = string.Empty;
}

public class CieConfig
{
    public string Issuer { get; set; } = string.Empty;
    public string AssertionConsumerServiceUrl { get; set; } = string.Empty;
    public string SingleLogoutUrl { get; set; } = string.Empty;
    public string CertificatePath { get; set; } = string.Empty;
    public string CertificatePassword { get; set; } = string.Empty;

    public string IdpCertificateBase64 { get; set; } = string.Empty;

    public string IdPMetadataUrl { get; set; } = string.Empty;    
    public string SsoUrl { get; set; } = string.Empty;
    public string SloUrl { get; set; } = string.Empty;
}
