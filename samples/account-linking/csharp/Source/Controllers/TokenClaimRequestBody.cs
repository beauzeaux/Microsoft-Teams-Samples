using System.Text.Json.Serialization;

namespace Microsoft.Teams.Samples.AccountLinking.Controllers;

public class TokenClaimRequestBody
{
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    [JsonPropertyName("code_verifier")]
    public string? CodeVerifier { get; set; }
}
