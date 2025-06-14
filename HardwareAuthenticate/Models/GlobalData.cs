namespace HardwareAuthenticate.Models;

using System.Text.Json.Serialization;

internal class GlobalData
{
    [JsonPropertyName("entries")]
    public Item[] Entries { get; set; }

    [JsonPropertyName("legalHeader")]
    public string LegalHeader { get; set; }

    [JsonPropertyName("nextUpdate")]
    public string NextUpdate { get; set; }

    [JsonPropertyName("no")]
    public int No { get; set; }
}
