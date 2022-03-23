using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.DataProtection;
using System.Text.Json;
using Microsoft.Extensions.Options;

using Microsoft.Teams.Samples.AccountLinking.ReplayValidation;

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
public sealed class OAuthStateService
{
    private readonly ILogger<OAuthStateService> _logger;

    private readonly IReplayValidator _replayValidator;

    private readonly ITimeLimitedDataProtector _dataProtector;

    private readonly TimeSpan _lifeSpan;

    public OAuthStateService(
        ILogger<OAuthStateService> logger,
        IReplayValidator replayValidator, 
        IDataProtectionProvider dataProtectionProvider, 
        IOptions<OAuthStateServiceOptions> options)
    {
        _logger = logger;
        _replayValidator = replayValidator;
        var protectorName = string.IsNullOrEmpty(options.Value.ProtectorName)
            ? (typeof(OAuthStateService).Assembly.FullName ?? nameof(OAuthStateService))
            : options.Value.ProtectorName;
        _dataProtector = dataProtectionProvider.CreateProtector(protectorName).ToTimeLimitedDataProtector();
        _lifeSpan = options.Value.ExpirationTime;
    }

    public async Task<string> GetStateAsync(string userId, string tenantId)
    {
        await Task.CompletedTask;
        var state = new OAuthStateObject
        {
            Id = Guid.NewGuid().ToString(),
            UserId = userId,
            TenantId = tenantId
        };

        var stateString = JsonSerializer.Serialize(state);
        var protectedString = _dataProtector.Protect(stateString, DateTimeOffset.Now + _lifeSpan);
        _logger.LogInformation("State out: {state}", protectedString);
        return protectedString;
    }

    public async Task<(string userId, string tenantId)> VerifyAsync(string state)
    {
        _logger.LogInformation("State in: {state}", state);
        string unprotectedStateString = _dataProtector.Unprotect(state, out DateTimeOffset validUntil);

        var stateObject = JsonSerializer.Deserialize<OAuthStateObject>(unprotectedStateString);
        if (stateObject == default)
        {
            _logger.LogWarning("Failed to deserialize the state object");
            return default;
        }

        var isValid = await _replayValidator.ClaimIdAsync(stateObject.Id, validUntil);

        if (!isValid)
        {
            throw new Exception("State replay exception");
        }

        return (stateObject.UserId, stateObject.TenantId);
    }
}
