using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Collections.Specialized;
using System.Web;

using Microsoft.Teams.Samples.AccountLinking.OAuth;

namespace Microsoft.Teams.Samples.AccountLinking.Controllers;

[AllowAnonymous]
[ApiController]
[Route("[controller]")]
public sealed class OAuthController : ControllerBase
{
    private readonly OAuthTokenProvider _tokenProvider;

    private readonly ILogger<OAuthController> _logger;

    private readonly OAuthOptions _options;

    public OAuthController(
        ILogger<OAuthController> logger,
        IOptions<OAuthOptions> options,
        OAuthTokenProvider tokenProvider)
    {
        _logger = logger;
        _options = options.Value;
        _tokenProvider = tokenProvider;
    }

    [HttpGet("start")]
    public IActionResult StartAuth([FromQuery] string? state)
    { 
        // Formulate the query string (strange hack so that the .ToString() gives us a proper query string)
        NameValueCollection oauthQueryParameters = HttpUtility.ParseQueryString(string.Empty);
        oauthQueryParameters.Add("client_id", _options.ClientId);
        oauthQueryParameters.Add("state", state);
        oauthQueryParameters.Add("redirect_uri", _options.AuthEndUri);
        var redirectUriBuilder = new UriBuilder(_options.AuthorizeUrl)
        {
            Query = oauthQueryParameters.ToString()
        };

        var redirectUri = redirectUriBuilder.Uri.ToString();
        return new RedirectResult(redirectUri);
    }

    [HttpGet("end")]
    public async Task<IActionResult> EndAuthAsync([FromQuery] string? state, [FromQuery] string? code)
    {
        if (code == default)
        {
            return new BadRequestObjectResult(new {
                Error = "No code in query parameters"
            });
        }

        if (state == default)
        {
            return new BadRequestObjectResult(new {
                Error = "No state in query parameters"
            });
        }
        
        await _tokenProvider.ClaimTokenAsync(state: state, code: code);

        // Return the 'authEnd' page to call the notifySuccess client-side
        return new VirtualFileResult("authEnd.html", "text/html");
    }
}

