namespace Microsoft.Teams.Samples.AccountLinking.OAuth;

/// <summary>
/// The mutable intermediate data used during the auth flows.
/// </summary>
public sealed class OAuthStateObject
{
    /// <summary>
    /// The state that the client of this application provided us. 
    /// NOTE: this is distinct from the state we pass to the OAuth provider which includes this state.
    /// </summary>
    /// <value></value>
    public string? ClientState { get; set; }
    /// <summary>
    /// The OAuth2.0 code returned from the service which we can exchange once for an access token.
    /// </summary>
    public string? OAuthCode { get; set; }
}