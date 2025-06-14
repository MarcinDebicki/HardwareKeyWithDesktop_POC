namespace HardwareAuthenticate.Models;

using System.Text.Json.Serialization;

internal class ClientDataJson
{
    [JsonPropertyName("challenge")]
    public string Challenge { get; set; }

    [JsonPropertyName("crossOrigin")]
    public bool? CrossOrigin { get; set; }
    [JsonPropertyName("origin")]
    public string Origin { get; set; }
    [JsonPropertyName("type")]
    public string Type { get; set; }
}
