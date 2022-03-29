using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.DataProtection;
using System.Text.Json;
using Microsoft.Extensions.Options;

using Microsoft.Teams.Samples.AccountLinking.ReplayValidation;
using System.Text;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.Teams.Samples.AccountLinking.OAuth;

/// <summary>
/// The OAuthStateService is responsible for encoding the tenant and user ids in a verifiable object with a limited lifespan. 
/// This "state" object is used in the OAuth flow to avoid csrf.
///  https://docs.microsoft.com/en-us/azure/active-directory/develop/reply-url#use-a-state-parameter 
/// </summary>
/// <remarks>
/// This uses the ASP.NET Core Data Protection library to handle the cryptographic verification of the encoded 'state' object.
/// To learn more see the documentation at: https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/introduction
/// </remarks> 
public sealed class OAuthStateService<TState> where TState : class?
{
    private readonly ILogger<OAuthStateService<TState>> _logger;

    private readonly IReplayValidator _replayValidator;

    private readonly ITimeLimitedDataProtector _dataProtector;

    private readonly TimeSpan _lifeSpan;

    public OAuthStateService(
        ILogger<OAuthStateService<TState>> logger,
        IReplayValidator replayValidator, 
        IDataProtectionProvider dataProtectionProvider, 
        IOptions<OAuthStateServiceOptions> options)
    {
        _logger = logger;
        _replayValidator = replayValidator;
        var protectorName = string.IsNullOrEmpty(options.Value.ProtectorName)
            ? (typeof(OAuthStateService<TState>).Assembly.FullName ?? nameof(OAuthStateService<TState>))
            : options.Value.ProtectorName;
        _dataProtector = dataProtectionProvider.CreateProtector(protectorName).ToTimeLimitedDataProtector();
        _lifeSpan = options.Value.ExpirationTime;
    }

    public Task<string> CreateStateAsync(string subject, string codeChallenge, TState? initialState)
    {
        var state = new OAuthStateWrapper<TState>()
        {
            Id = Guid.NewGuid().ToString(),
            Subject = subject,
            CodeChallenge = codeChallenge,
            State = initialState
        };
        var stateString = JsonSerializer.Serialize(state);
        var protectedString = _dataProtector.Protect(stateString, DateTimeOffset.Now + _lifeSpan);
        return Task.FromResult(protectedString);
    }

    public Task<TState?> GetMutableStateAsync(string state)
    {
        string unprotectedStateString = _dataProtector.Unprotect(state, out DateTimeOffset validUntil);
        var stateObject = JsonSerializer.Deserialize<OAuthStateWrapper<TState>>(unprotectedStateString);
        return Task.FromResult(stateObject?.State);
    }

    public Task<string> SetMutableStateAsync(string state, TState? mutableState)
    {
        string unprotectedStateString = _dataProtector.Unprotect(state, out DateTimeOffset validUntil);
        var stateObject = JsonSerializer.Deserialize<OAuthStateWrapper<TState>>(unprotectedStateString);
        if (stateObject == default)
        {
            throw new Exception("Invalid state object");
        }
        stateObject.State = mutableState;
        var serializedState = JsonSerializer.Serialize(stateObject);
        var nextState = _dataProtector.Protect(serializedState, validUntil);
        return Task.FromResult(nextState);
    }

    public async Task<TState?> VerifyAsync(string state, string subject, string codeVerifier)
    {
        string unprotectedStateString = _dataProtector.Unprotect(state, out DateTimeOffset validUntil);

        var stateObject = JsonSerializer.Deserialize<OAuthStateWrapper<TState>>(unprotectedStateString);
        if (stateObject == default)
        {
            _logger.LogWarning("Failed to deserialize the state object");
            throw new Exception("Verification failed, state object invalid");
        }

        if (!string.Equals(stateObject.Subject, subject, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Verification failed, subject mismatch: {expected} | {actual}", stateObject.Subject, subject);
            throw new Exception("Verification failed, subject mismatch");
        }

        // transform the code verifier and check it against the codeChallenge
        // See: https://datatracker.ietf.org/doc/html/rfc7636
        var transformedVerifier = Base64UrlEncodeSha256(codeVerifier);
        if (!string.Equals(stateObject.CodeChallenge, transformedVerifier, StringComparison.Ordinal))
        {
            _logger.LogWarning("Failed to code verifier invalid: [{challenge}] [{provided}] [{tProvided}]", stateObject.CodeChallenge, codeVerifier, transformedVerifier);
            throw new Exception("Verification failed, code challenge");
        }

        var isValid = await _replayValidator.ClaimIdAsync(stateObject.Id, validUntil);

        if (!isValid)
        {
            throw new Exception("Verification failed, replay");
        }

        return stateObject.State;
    }

    public static string Base64UrlEncodeSha256(string value)
    {
        using var hash = SHA256.Create();
        var hashBytes = hash.ComputeHash(Encoding.ASCII.GetBytes(value));
        return Base64UrlEncoder.Encode(hashBytes);
    }
}
