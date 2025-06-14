namespace HardwareAuthenticate.ViewModels;

using System;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.Input;
using DSInternals.Win32.WebAuthn;
using AuthenticatorAssertionResponse = DSInternals.Win32.WebAuthn.AuthenticatorAssertionResponse;

/*
   127.0.0.1 test0.local
   127.0.0.1 test1.local
   127.0.0.1 test2.local
   127.0.0.1 test3.local
   127.0.0.1 test4.local
   127.0.0.1 test5.local
 */

public partial class MainWindowViewModel : ViewModelBase
{
    public string AAGuid { get; set; }
    public AuthenticatorAssertionResponse AuthenticatorAssertionResponse { get; set; }
    public string AuthenticatorAssertionResponseSerialize { get; set; }

    public byte[] Challenge { get; set; }
    public string ChallengeSerialize { get; set; }

    public string Error { get; set; }

    public ICommand GetAssertion { get; }
    public ICommand MakeNewCredential { get; }

    public PublicKeyCredential PublicKeyCredential { get; set; }
    public string PublicKeyCredentialSerialize { get; set; }
    public ICommand ValidateAssertion { get; }
    public string ValidationResult { get; set; }

    private WebAuthService WebAuthService { get; }

    public MainWindowViewModel()
    {
        this.MakeNewCredential = new AsyncRelayCommand(this.MakeNewCredentialExecute);
        this.GetAssertion = new AsyncRelayCommand(this.GetAssertionExecute);
        this.ValidateAssertion = new RelayCommand(this.ValidateAssertionExecute);

        this.WebAuthService = new WebAuthService();

        var publicKeyCredential = JsonSerializer.Deserialize<PublicKeyCredential>(
            """
            {
              "id": "FpuyVJhEeqnEXCCDrtoLybA3s-kGhbDw_UJ9AMUBeKk",
              "response": {
                "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgc8xAZVSkwHtK8Ug6ul7MPNHAJselxTW5ZxerOCETNZ4CID5FCHveXHtYK5aRQrfEe4kqHzO4JDBAszZnEka51N-HY3g1Y4FZAkAwggI8MIIB4aADAgECAgIG6zAKBggqhkjOPQQDAjCBmTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMREwDwYDVQQHDAhTYW4gSm9zZTEYMBYGA1UECgwPU3luYXB0aWNzLCBJbmMuMQwwCgYDVQQLDANQQ0QxFTATBgNVBAMMDFN5bmFwdGljcyBDQTErMCkGCSqGSIb3DQEJARYcY2VydC1hdXRob3JpdHlAc3luYXB0aWNzLmNvbTAgFw0yMDA2MDkwMjAwMDlaGA8yMDUwMDYwOTAyMDAwOVowfzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMREwDwYDVQQHDAhTYW4gSm9zZTEYMBYGA1UECgwPU3luYXB0aWNzLCBJbmMuMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRIwEAYDVQQDDAlTeW5hcHRpY3MwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATAGgosW6qE_IgVhf98o1sL4dJSe2RQA8DPCZmJ4CWNcmgaCG5VFnnpYHfPTc-DG287GcV4O4EVodiDf9c0bUL6ozAwLjAhBgsrBgEEAYLlHAEBBAQSBBDZSinZUt1CR5wti4GLYQOJMAkGA1UdEwQCMAAwCgYIKoZIzj0EAwIDSQAwRgIhAPKSGcK_6QxiGMXMYoqB3SCOvoL9H-5qppx8SxbyPhzZAiEAkiNPfYryeLqfvr7g3TokqJjt_PBUrAuvjSHKCKV4OoxoYXV0aERhdGFYpHw1JBgOpsyhvt0RUGLxVEjJ4PKl4bRLsvBYMs_vv2PxRQAAAAHZSinZUt1CR5wti4GLYQOJACAWm7JUmER6qcRcIIOu2gvJsDez6QaFsPD9Qn0AxQF4qaUBAgMmIAEhWCBrLmf9tZCXpCZl5P53Wi2krCZsB5j65Lxa8FXdSrs8zSJYIGCTjUKe2KV1UPkUaLJxnfKedJMo4vsve8IaFq3P4Ol4",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUGdVTVYtb2IwaGx1OVFobk1WaWE0WjNBd3V0WGNCRllRanVxblRfS2pkbEJDQWpUVVgwMVlDU1BPQV9ieWZrT0pSY3N2dFVZb0pxT0FUVVp3dlVsUjRFTTBsOWhZbnl1SUpnUVlEQlhTdFNJNjNQdTZKaGczUXEyZ1FVdDUySi1oZkRLaHJSbVhVekpCcUNETlJrMW02SUJkaXpJS3IyV2xocEVpT1dac0tVIiwib3JpZ2luIjoiaHR0cHM6Ly90ZXN0MC5sb2NhbCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
              },
              "clientExtensionResults": {}
            }
            """);

        var aaguid = this.WebAuthService.GetAAGuid(publicKeyCredential);
    }

    private async Task GetAssertionExecute(CancellationToken cancellationToken = default)
    {
        try
        {
            this.Challenge = RandomNumberGenerator.GetBytes(128);
            this.AuthenticatorAssertionResponse = await this.WebAuthService.GetAssertionAsync(this.Challenge, cancellationToken);
            this.AuthenticatorAssertionResponseSerialize = JsonSerializer.Serialize(this.AuthenticatorAssertionResponse, new JsonSerializerOptions { WriteIndented = true });
            this.ChallengeSerialize = Convert.ToBase64String(this.Challenge);
            OnPropertyChanged(nameof(this.AuthenticatorAssertionResponseSerialize));
            OnPropertyChanged(nameof(this.ChallengeSerialize));
        }
        catch (Exception exception)
        {
            this.Error = "Error: " + exception.Message;
            OnPropertyChanged(nameof(this.Error));
        }
    }

    private async Task MakeNewCredentialExecute(CancellationToken cancellationToken = default)
    {
        try
        {
            this.PublicKeyCredential = await this.WebAuthService.MakeNewCredentialAsync(cancellationToken);
            this.PublicKeyCredentialSerialize = JsonSerializer.Serialize(this.PublicKeyCredential, new JsonSerializerOptions { WriteIndented = true });
            this.AAGuid = this.WebAuthService.GetAAGuid(this.PublicKeyCredential).ToString();

            OnPropertyChanged(nameof(this.PublicKeyCredentialSerialize));
            OnPropertyChanged(nameof(this.AAGuid));
        }
        catch (Exception exception)
        {
            this.Error = "Error: " + exception.Message;
            OnPropertyChanged(nameof(this.Error));
        }
    }

    private void ValidateAssertionExecute()
    {
        var result = this.WebAuthService.Validate(this.PublicKeyCredential, this.AuthenticatorAssertionResponse, this.Challenge);

        if (result is true)
        {
            this.ValidationResult = "Correct";
        }
        else
        {
            this.ValidationResult = "Total failure";
        }

        OnPropertyChanged(nameof(this.ValidationResult));
    }
}
