# HardwareKeyWithDesktop_POC

Create FIDO2 credentials (WebAuthService.MakeNewCredentialAsync)

Create Authenticator Assertion (WebAuthService.GetAssertionAsync)

And check if the AuthenticatorAssertionResponse matches the PublicKeyCredential generated earlier (WebAuthService.Validate)


My key supports only ES256, so creation and validation is limited to the WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 algorithm
