using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Collections.Specialized;
using System.Web;

using Microsoft.Teams.Samples.AccountLinking.OAuth;
using Microsoft.Teams.Samples.AccountLinking.AccountLinkingState;

namespace Microsoft.Teams.Samples.AccountLinking.Controllers;

[AllowAnonymous]
[ApiController]
[Route("[controller]")]
public sealed class OAuthController : ControllerBase
{
    private readonly AccountLinkingStateService<OAuthStateObject> _stateService;

    private readonly ILogger<OAuthController> _logger;

    private readonly OAuthOptions _options;

    public OAuthController(
        ILogger<OAuthController> logger,
        IOptions<OAuthOptions> options,
        AccountLinkingStateService<OAuthStateObject> stateService)
    {
        _logger = logger;
        _options = options.Value;
        _stateService = stateService;
    }

    [HttpGet("start")]
    public async Task<IActionResult> StartAuthAsync(
        [FromQuery] string? state,
        [FromQuery(Name="acct_state")] string? accountLinkingState)
    { 
        if (state == default)
        {
            return new BadRequestObjectResult(new {
                Error = "No state in query parameters"
            });
        }

        if (accountLinkingState == default)
        {
            return new BadRequestObjectResult(new {
                Error = "No state in query parameters"
            });
        }

        // Encode the 'state' into the 'tokenState'
        var mutableState = (await _stateService.GetMutableStateAsync(accountLinkingState)) ?? new OAuthStateObject();
        mutableState.ClientState = state;
        var nextState = await _stateService.SetMutableStateAsync(accountLinkingState, mutableState);

        // Formulate the query string (strange hack so that the .ToString() gives us a proper query string)
        NameValueCollection oauthQueryParameters = HttpUtility.ParseQueryString(string.Empty);
        oauthQueryParameters.Add("client_id", _options.ClientId);
        // we use our acct linking state as the 'state' parameter in the external OAuth.
        oauthQueryParameters.Add("state", nextState); 
        oauthQueryParameters.Add("redirect_uri", _options.AuthEndUri);
        var redirectUriBuilder = new UriBuilder(_options.AuthorizeUrl)
        {
            Query = oauthQueryParameters.ToString()
        };

        var redirectUri = redirectUriBuilder.Uri.ToString();
        return new RedirectResult(redirectUri);
    }

    [HttpGet("end")]
    public async Task<IActionResult> EndAuthAsync(
        [FromQuery(Name="state")] string? accountLinkingState,
        [FromQuery] string? code)
    { 
        if (accountLinkingState == default)
        {
             return new BadRequestObjectResult(new {
                Error = "No state in query parameters"
            }); 
        }

        if (code == default)
        {
             return new BadRequestObjectResult(new {
                Error = "No code in query parameters"
            }); 
        }

        // encode the oauth 'code' into the state so we can re-brand the state as the 
        // 'code' returned to the client.
        var mutableState = (await _stateService.GetMutableStateAsync(accountLinkingState)) ?? new OAuthStateObject();
        mutableState.OAuthCode = code;

        var nextState = await _stateService.SetMutableStateAsync(accountLinkingState, mutableState);

        // We send back our internal 'state' as the 'code' that the client will use to claim the auth token
        // and send back the client's state as the 'state' parameter to keep harmony with existing protocols.
        NameValueCollection queryParams = HttpUtility.ParseQueryString(string.Empty);
        queryParams.Add("state", mutableState.ClientState);
        queryParams.Add("code", nextState);
        //TODO: the auth end url should be encoded into the 'state'
        var redirectUriBuilder = new UriBuilder(_options.AuthEndRedirect) 
        {
            Query = queryParams.ToString()
        };

        var redirectUri = redirectUriBuilder.Uri.ToString();
        return new RedirectResult(redirectUri);
    }
}

