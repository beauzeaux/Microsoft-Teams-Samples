using System.Text.Json.Serialization;

namespace Microsoft.Teams.Samples.AccountLinking;

/// <summary>
/// The wrapper format for the auth response we get from the 'authEnd' page's call to notify success
/// </summary>
public sealed class AuthResponse
{
    [JsonPropertyName("state")]
    public string State { get; set; } = string.Empty;

    [JsonPropertyName("code")]
    public string Code { get; set; } = string.Empty;
}