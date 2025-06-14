namespace HardwareAuthenticate.Models;

using System.Text.Json.Serialization;

internal class MetadataStatement
{
    [JsonPropertyName("aaguid")]
    public string AAGuid { get; set; }

    [JsonPropertyName("authenticationAlgorithms")]
    public string[] AuthenticationAlgorithms { get; set; }

    [JsonPropertyName("authenticatorVersion")]
    public int AuthenticatorVersion { get; set; }

    [JsonPropertyName("description")]
    public string Description { get; set; }

    [JsonPropertyName("icon")]
    public string Icon { get; set; }

    [JsonPropertyName("protocolFamily")]
    public string ProtocolFamily { get; set; }
}
