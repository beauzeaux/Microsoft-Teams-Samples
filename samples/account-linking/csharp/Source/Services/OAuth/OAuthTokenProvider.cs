using System.Collections.Specialized;
using System.Text.Json;
using System.Web;
using Microsoft.Extensions.Options;
using Microsoft.Teams.Samples.AccountLinking.UserTokenStorage;

namespace Microsoft.Teams.Samples.AccountLinking.OAuth;

/// <summary>
/// Abstraction over the OAuth2.0 logic / flows to enable token caching, refreshing and fetching.
/// </summary>
public sealed class OAuthTokenProvider
{
    private readonly ILogger<OAuthTokenProvider> _logger;

    private readonly OAuthStateService _oAuthStateService;

    private readonly OAuthServiceClient _oAuthServiceClient;

    private readonly IUserTokenStore _userTokenStore;

    private readonly OAuthOptions _options;

    public OAuthTokenProvider(
        ILogger<OAuthTokenProvider> logger,
        IOptions<OAuthOptions> options,
        OAuthStateService oAuthStateService,
        OAuthServiceClient oAuthServiceClient,
        IUserTokenStore userTokenStore)
    {
        _logger = logger;
        _options = options.Value;
        _oAuthStateService = oAuthStateService;
        _oAuthServiceClient = oAuthServiceClient;
        _userTokenStore = userTokenStore;
    }

    public async Task<AccessTokenResultBase> GetAccessTokenAsync(string tenantId, string userId)
    {
        var tokenDtoString = await _userTokenStore.GetTokenAsync(tenantId, userId);
        if (tokenDtoString == default)
        {
            _logger.LogInformation("Underlying store contained no token, returning null");
            return await GetNeedsConsentResultAsync(tenantId: tenantId, userId: userId);
        }

        var tokenDto = JsonSerializer.Deserialize<OAuthUserTokenDto>(tokenDtoString);
        if (tokenDto == default)
        {
            _logger.LogWarning("Token stored was valid json, but not valid DTO! Did the schema change?");
            return await GetNeedsConsentResultAsync(tenantId: tenantId, userId: userId);
        }

        _logger.LogInformation(
            "Token expired? [{isExpired}]: [{timeDelta}]",
            DateTime.Now >= tokenDto.AccessTokenExpiration,
            DateTime.Now - tokenDto.AccessTokenExpiration);

        // If the 'cached' token is still valid don't do the refresh.
        if (tokenDto.AccessTokenExpiration >= DateTime.Now)
        {
            return new AccessTokenResult
            {
                AccessToken = tokenDto.AccessToken,
            };
        }

        _logger.LogInformation("Performing oAuth refresh flow");
        var jsonBody = await _oAuthServiceClient.RefreshAccessTokenAsync(tokenDto.RefreshToken);
        if (jsonBody == default)
        {
            return await GetNeedsConsentResultAsync(tenantId: tenantId, userId: userId);
        }

        string accessToken = jsonBody.AccessToken;
        long expirationSeconds = jsonBody.ExpiresInSeconds;
        // If we get a refresh token in the response, we need to replace the refresh token. Otherwise re-use the current refresh token.
        string nextRefreshToken = jsonBody.RefreshToken ?? tokenDto.RefreshToken;
        
        var dto = new OAuthUserTokenDto
        {
            AccessToken = accessToken,
            AccessTokenExpiration = DateTimeOffset.Now + TimeSpan.FromSeconds(expirationSeconds),
            RefreshToken = nextRefreshToken
        };

        var serializedDto = JsonSerializer.Serialize(dto);
        await _userTokenStore.SetTokenAsync(
            tenantId: tenantId,
            userId:userId,
            token: serializedDto);

        return new AccessTokenResult
        {
            AccessToken = accessToken,
        };
    }

    public async Task ClaimTokenAsync(string state, string code)
    {
        var (userId, tenantId) = await _oAuthStateService.VerifyAsync(state);
        var oAuthResult = await _oAuthServiceClient.ClaimCodeAsync(code);
        
        var dto = new OAuthUserTokenDto
        {
            AccessToken = oAuthResult.AccessToken,
            AccessTokenExpiration = DateTimeOffset.Now + TimeSpan.FromSeconds(oAuthResult.ExpiresInSeconds),
            RefreshToken = oAuthResult.RefreshToken
        };

        var serializedDto = JsonSerializer.Serialize(dto);

        await _userTokenStore.SetTokenAsync(tenantId: tenantId, userId: userId, serializedDto);
    }

    public async Task LogoutAsync(string tenantId, string userId)
    {
        await _userTokenStore.DeleteTokenAsync(tenantId: tenantId, userId: userId);
    }

    private async Task<NeedsConsentResult> GetNeedsConsentResultAsync(string tenantId, string userId)
    {
        var state = await _oAuthStateService.GetStateAsync(tenantId: tenantId, userId: userId);
        NameValueCollection queryParameters = HttpUtility.ParseQueryString(string.Empty);
        queryParameters.Add("state", state);
        var redirectUri = new UriBuilder(_options.AuthStartUri)
        {
            Query = queryParameters.ToString(),
            Port = -1 // Otherwise the ToString will include the port number?
        };
        return new NeedsConsentResult
        {
            RedirectUri = redirectUri.ToString(),
        };
    } 
}

public abstract class AccessTokenResultBase {}

public sealed class NeedsConsentResult : AccessTokenResultBase
{
    public string RedirectUri { get; set; } = string.Empty;
}

public sealed class AccessTokenResult : AccessTokenResultBase
{
    public string AccessToken { get; set; } = string.Empty;

    public DateTimeOffset ExpirationTime { get; set; }
}
