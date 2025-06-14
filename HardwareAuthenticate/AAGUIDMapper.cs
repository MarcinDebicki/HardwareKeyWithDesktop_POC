namespace HardwareAuthenticate;

using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Text.Json;
using HardwareAuthenticate.Models;

internal class AAGUIDMapper
{
    public AAGUIDMapper()
    {
        if (File.Exists("Resources\\blob.jwt"))
        {
            var blob = File.ReadAllText("Resources\\blob.jwt");

            var handler = new JwtSecurityTokenHandler
            {
                MaximumTokenSizeInBytes = 10 * 1024 * 1024, // np. 10 MB
            };

            var jwt = handler.ReadJwtToken(blob);
            var payloadJson = jwt.Payload.SerializeToJson();

            var obj = JsonSerializer.Deserialize<GlobalData>(payloadJson);
        }
    }
}
