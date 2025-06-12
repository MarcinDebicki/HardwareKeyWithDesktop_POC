namespace HardwareAuthenticate;

using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using DSInternals.Win32.WebAuthn;
using DSInternals.Win32.WebAuthn.COSE;
using PeterO.Cbor;
using AuthenticatorAssertionResponse = DSInternals.Win32.WebAuthn.AuthenticatorAssertionResponse;
using Base64UrlConverter = DSInternals.Win32.WebAuthn.Base64UrlConverter;

internal class WebAuthService
{
    private const string APP_NAME = "My App";
    private const string ORIGIN = "https://test0.local";

    /// <summary>
    ///     Important!
    ///     Create an entry in the C:Windows file C:\Windows\System32\drivers\etc\hosts:
    ///     127.0.0.1 test0.local
    /// </summary>
    private const string RP_ID = "test0.local";

    private WebAuthnApi webAuthApi;

    public WebAuthService()
    {
        this.webAuthApi = new WebAuthnApi();
    }

    public async Task<AuthenticatorAssertionResponse> GetAssertionAsync(byte[] challenge, CancellationToken cancellationToken = default)
    {
        var authenticationExtensionsClientInputs = new AuthenticationExtensionsClientInputs
        {
            AppID = APP_NAME,
            CredProtect = UserVerification.Required,
            CredentialBlob = null,
            EnforceCredProtect = true,
            GetCredentialBlob = false,
            HmacCreateSecret = false,
            HmacGetSecret = null,
            MinimumPinLength = false,
        };

        var result = await this.webAuthApi.AuthenticatorGetAssertionAsync(
            RP_ID,
            challenge,
            UserVerificationRequirement.Required,
            AuthenticatorAttachment.Any,
            timeoutMilliseconds: 120000,
            allowCredentials: null,
            authenticationExtensionsClientInputs,
            CredentialLargeBlobOperation.None,
            largeBlob: null,
            browserInPrivateMode: false,
            linkedDevice: null,
            WindowHandle.ForegroundWindow,
            cancellationToken
        );

        return result;
    }

    public async Task<PublicKeyCredential> MakeNewCredentialAsync(CancellationToken cancellationToken = default)
    {
        var relyingPartyInformation = new RelyingPartyInformation
        {
            Id = RP_ID,
            Name = APP_NAME,
        };

        var userEntity = new UserInformation
        {
            Id = RandomNumberGenerator.GetBytes(32),
            Name = "any user",
            DisplayName = "User display name",
        };

        var challenge = RandomNumberGenerator.GetBytes(128);

        var algorithms = new Algorithm[]
        {
            Algorithm.ES256,
        };

        var timeout = 50000;

        var result = await this.webAuthApi.AuthenticatorMakeCredentialAsync(
            relyingPartyInformation,
            userEntity,
            challenge,
            UserVerificationRequirement.Required,
            AuthenticatorAttachment.CrossPlatform,
            requireResidentKey: true,
            algorithms,
            AttestationConveyancePreference.Direct,
            timeout,
            extensions: null,
            excludeCredentials: null,
            EnterpriseAttestationType.None,
            LargeBlobSupport.None,
            preferResidentKey: false,
            browserInPrivateMode: false,
            enablePseudoRandomFunction: false,
            linkedDevice: null,
            WindowHandle.ForegroundWindow,
            cancellationToken
        );

        return result;
    }

    public bool Validate(
        PublicKeyCredential registrationCredential,
        AuthenticatorAssertionResponse assertionResponse,
        byte[] challenge)
    {
        // 1. Check if the challenge matches
        if (this.ValidateChallenge(assertionResponse.ClientDataJson, challenge) is false)
        {
            return false;
        }

        // 2. Check origin and operation type in clientDataJSON
        if (this.ValidateClientData(assertionResponse.ClientDataJson) is false)
        {
            return false;
        }

        // 3. Check out Relying Party ID
        if (!this.ValidateRelyingPartyId(assertionResponse.AuthenticatorData))
        {
            return false;
        }

        // 4. Check the User Present (UP) flag
        if (!this.ValidateUserPresence(assertionResponse.AuthenticatorData))
        {
            return false;
        }

        // 5. Verify signature
        return this.ValidateSignature(
            registrationCredential,
            assertionResponse.AuthenticatorData,
            assertionResponse.ClientDataJson,
            assertionResponse.Signature);
    }

    private class ClientDataJson
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

    private byte[] ExtractPublicKeyFromAttestationObjectBytes(byte[] attestationObject)
    {
        try
        {
            var cborObject = CBORObject.DecodeFromBytes(attestationObject);
            var authData = cborObject["authData"].GetByteString();

            var result = this.ExtractPublicKeyFromAuthData(authData);

            return result;
        }
        catch
        {
            return null;
        }
    }

    private byte[] ExtractPublicKeyFromAuthData(byte[] authData)
    {
        try
        {
            // authData:
            // Bytes 0-31: rpIdHash (32 bytes)
            // Byte 32: flags (1 byte)
            // Bytes 33-36: signCount (4 bytes)
            // Bytes 37+: attestedCredentialData (if AT flags are set)

            if (authData.Length < 37)
            {
                return null;
            }

            var flags = authData[32];
            var attestedCredentialDataFlag = (flags & 0x40) != 0; // Bit 6 = AT (Attested credential data included)

            if (!attestedCredentialDataFlag)
            {
                return null; // No credential data available
            }

            // attestedCredentialData:
            // Bytes 0-15: aaguid (16 bytes)
            // Bytes 16-17: credentialIdLength (2 bytes, big endian)
            // Bytes 18-(18+credentialIdLength-1): credentialId
            // Remaining bytes: credentialPublicKey (CBOR encoded)

            var credentialIdLength = authData[37 + 16] << 8 | authData[37 + 17];
            var publicKeyStart = 37 + 16 + 2 + credentialIdLength; // aaguid + length + credentialId

            if (authData.Length <= publicKeyStart)
            {
                return null;
            }

            // The public key is encoded in CBOR
            var publicKeyCbor = new byte[authData.Length - publicKeyStart];
            Array.Copy(authData, publicKeyStart, publicKeyCbor, destinationIndex: 0, publicKeyCbor.Length);

            return publicKeyCbor; // This is the key in CBOR COSE format
        }
        catch
        {
            return null;
        }
    }

    private bool ValidateChallenge(byte[] clientDataJson, byte[] expectedChallenge)
    {
        try
        {
            var clientData = JsonSerializer.Deserialize<ClientDataJson>(clientDataJson);
            var receivedChallenge = Base64UrlConverter.FromBase64UrlString(clientData.Challenge);
            var result = receivedChallenge.AsSpan().SequenceEqual(expectedChallenge);

            return result;
        }
        catch
        {
            return false;
        }
    }

    private bool ValidateClientData(byte[] clientDataJson)
    {
        try
        {
            var clientData = JsonSerializer.Deserialize<ClientDataJson>(clientDataJson);

            // Check the type of operation
            if (clientData.Type != "webauthn.get")
            {
                return false;
            }

            // Check out origin+
            var urlclientDataOrigin = new Uri(clientData.Origin);
            var urlOrigin = new Uri(ORIGIN);

            if (urlclientDataOrigin.Host != urlOrigin.Host)
            {
                return false;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool ValidateRelyingPartyId(byte[] authenticatorData)
    {
        try
        {
            // RP ID hash is in the first 32 bytes of authenticatorData
            var rpIdHashFromResponse = new byte[32];
            Array.Copy(authenticatorData, sourceIndex: 0, rpIdHashFromResponse, destinationIndex: 0, length: 32);

            // Calculate RP ID hash
            using var sha256 = SHA256.Create();
            var expectedRpIdHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(RP_ID));

            return rpIdHashFromResponse.AsSpan().SequenceEqual(expectedRpIdHash);
        }
        catch
        {
            return false;
        }
    }

    private bool ValidateSignature(
        PublicKeyCredential registrationCredential,
        byte[] authenticatorData,
        byte[] clientDataJson,
        byte[] signature)
    {
        try
        {
            // Get the public key from the registration data
            var attestationResponse = registrationCredential.AuthenticatorResponse;

            if (attestationResponse == null)
            {
                return false;
            }

            // Conversion to public key using CBOR
            var publicKeyBytes = this.ExtractPublicKeyFromAttestationObjectBytes(attestationResponse.AttestationObject);

            if (publicKeyBytes == null)
            {
                return false;
            }

            // Create signature verification data
            using var sha256 = SHA256.Create();
            var clientDataHash = sha256.ComputeHash(clientDataJson);

            var signedData = new byte[authenticatorData.Length + clientDataHash.Length];
            Array.Copy(authenticatorData, sourceIndex: 0, signedData, destinationIndex: 0, authenticatorData.Length);
            Array.Copy(clientDataHash, sourceIndex: 0, signedData, authenticatorData.Length, clientDataHash.Length);

            // Verify signature (implementation depends on key algorithm)
            // Although only ES256 algorithm is currently implemented
            return this.VerifySignatureWithPublicKey(publicKeyBytes, signedData, signature);
        }
        catch
        {
            return false;
        }
    }

    private bool ValidateUserPresence(byte[] authenticatorData)
    {
        try
        {
            // Flags are in the 33rd byte (index 32)
            if (authenticatorData.Length < 33)
            {
                return false;
            }

            var flags = authenticatorData[32];

            // Bit 0 = User Present (UP)
            return (flags & 0x01) != 0;
        }
        catch
        {
            return false;
        }
    }

    private bool VerifyES256Signature(CBORObject coseKey, byte[] signedData, byte[] signature)
    {
        try
        {
            var curve = coseKey[-1].AsInt32(); // crv

            if (curve != 1) // P-256
            {
                return false;
            }

            var x = coseKey[-2].GetByteString(); // x coordinate (32 bytes)
            var y = coseKey[-3].GetByteString(); // y coordinate (32 bytes)

            var ecParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = x,
                    Y = y,
                },
            };

            using var eCDsa = ECDsa.Create(ecParams);

            var result = eCDsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

            return result;
        }
        catch
        {
            return false;
        }
    }

    private bool VerifySignatureWithPublicKey(byte[] publicKeyBytes, byte[] signedData, byte[] signature)
    {
        try
        {
            // Parse COSE Key with CBOR
            var coseKey = CBORObject.DecodeFromBytes(publicKeyBytes);

            // Check the algorithm (kty = key type, alg = algorithm)
            var keyType = coseKey[1].AsInt32(); // kty (1)
            var algorithm = coseKey[3].AsInt32(); // alg (3)

            switch (algorithm)
            {
                case -7: // ES256 (ECDSA with P-256 and SHA-256)
                    return this.VerifyES256Signature(coseKey, signedData, signature);

                default:
                    return false; // Unsupported algorithm
            }
        }
        catch
        {
            return false;
        }
    }
}
