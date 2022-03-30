namespace Microsoft.Teams.Samples.AccountLinking.AccountLinkingState;

/// <summary>
/// The data that needs to be carried through the OAuth flow for later use when the login/consent is completed.
/// 
/// This class wraps around an opaque 'State' which can be used for the mutable values we need to get / set between
/// stages in the auth flow(s)
/// </summary>
public sealed class AccountLinkingToken<TState> where TState : class?
{
    public string Id { get; set; } = string.Empty;

    public string Subject { get; set; } = string.Empty;

    public string CodeChallenge { get; set; } = string.Empty;

    public TState? State { get; set; } = default;
}