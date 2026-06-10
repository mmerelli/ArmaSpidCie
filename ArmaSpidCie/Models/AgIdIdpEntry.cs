using System.Text.Json.Serialization;

namespace ArmaSpidCie.Models
{
    public class AgIdIdpEntry
    {
        [JsonPropertyName("entity_id")]
        public string? EntityId { get; set; }

        [JsonPropertyName("organization_name")]
        public string? OrganizationName { get; set; }

        [JsonPropertyName("logo_uri")]
        public string? LogoUri { get; set; }

        [JsonPropertyName("single_sign_on_service")]
        public List<SamlService>? SingleSignOnService { get; set; }

        [JsonPropertyName("single_logout_service")]
        public List<SamlService>? SingleLogoutService { get; set; }

        [JsonPropertyName("signing_certificate_x509")]
        public List<string> signing_certificate_x509 { get; set; } = [];
    }

    public class SamlService
    {
        [JsonPropertyName("binding")]
        public string? Binding { get; set; }

        [JsonPropertyName("location")]
        public string? Location { get; set; }
    }
}
