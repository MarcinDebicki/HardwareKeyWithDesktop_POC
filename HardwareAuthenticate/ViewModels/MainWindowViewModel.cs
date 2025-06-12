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
            OnPropertyChanged(nameof(this.PublicKeyCredentialSerialize));
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
