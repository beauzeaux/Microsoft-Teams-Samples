using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Teams.Samples.AccountLinking.OAuth;
using Microsoft.Identity.Web.Resource;
using System.Security.Claims;
using Microsoft.Identity.Web;

namespace Microsoft.Teams.Samples.AccountLinking.Controllers;

[ApiController]
[Route("[controller]")]
public sealed class AccountLinkingController : ControllerBase
{
    private readonly OAuthTokenProvider _tokenProvider;

    private readonly ILogger<AccountLinkingController> _logger;

    private readonly OAuthOptions _options;

    public AccountLinkingController(
        ILogger<AccountLinkingController> logger,
        IOptions<OAuthOptions> options,
        OAuthTokenProvider tokenProvider)
    {
        _logger = logger;
        _options = options.Value;
        _tokenProvider = tokenProvider;
    }

    [AllowAnonymous]
    [HttpGet("authUrl")]
    public async Task<IActionResult> CreateAuthorizationUrl(
        [FromQuery(Name="code_challenge")] string? codeChallenge)
    {
        if (codeChallenge == default)
        {
            return new BadRequestObjectResult(new {
                Error = "No code challenge in query parameters"
            });
        }
        var consentUrl = await _tokenProvider.GetConsentUriAsync(codeChallenge: codeChallenge);
        return new OkObjectResult(new {
            consentUrl
        });
    }

    [Authorize]
    [RequiredScope(RequiredScopesConfigurationKey = "AzureAd:Scopes")]
    [HttpPut("claim")]
    public async Task<IActionResult> ClaimTokenAsync(
        [FromBody] TokenClaimRequestBody tokenClaimRequest)
    {
        if (tokenClaimRequest.Code == default)
        {
            return new BadRequestObjectResult(new {
                Error = "No code in query parameters"
            });
        }

        if (tokenClaimRequest.CodeVerifier == default)
        {
            return new BadRequestObjectResult(new {
                Error = "No code verifier in query parameters"
            });
        }

        var userId = User.FindFirstValue(ClaimConstants.ObjectId);
        var tenantId = User.FindFirstValue(ClaimConstants.TenantId);

        await _tokenProvider.ClaimTokenAsync(
            accountLinkingToken: tokenClaimRequest.Code, // our 'state' was given back to the caller as the 'code' for claiming
            tenantId: tenantId,
            userId: userId,
            codeVerifier: tokenClaimRequest.CodeVerifier);

        return new OkResult();
    }
}