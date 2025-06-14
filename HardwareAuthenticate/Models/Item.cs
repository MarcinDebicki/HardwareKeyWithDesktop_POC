namespace HardwareAuthenticate.Models;

using System;
using System.Text.Json.Serialization;

internal class Item
{
    [JsonPropertyName("aaguid")]
    public Guid AAGuid { get; set; }

    [JsonPropertyName("metadataStatement")]
    public MetadataStatement MetadataStatement { get; set; }
}
