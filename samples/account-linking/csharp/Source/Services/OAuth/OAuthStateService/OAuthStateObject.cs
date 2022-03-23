namespace Microsoft.Teams.Samples.AccountLinking.OAuth;

/// <summary>
/// The data that needs to be carried through the OAuth flow for later use when the login/consent is completed.
/// 
/// We use the 'Id' member to detect if there has been a replay of the same login.
/// </summary>
public sealed class OAuthStateObject
{
    public string Id { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public string TenantId { get; set; } = string.Empty;
}