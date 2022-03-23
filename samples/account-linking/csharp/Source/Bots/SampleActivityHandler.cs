using Microsoft.Bot.Builder;
using Microsoft.Bot.Builder.Dialogs;
using Microsoft.Bot.Builder.Teams;
using Microsoft.Bot.Schema;
using Microsoft.Bot.Schema.Teams;
using Microsoft.Teams.Samples.AccountLinking.OAuth;
using Microsoft.Teams.Samples.AccountLinking.GitHub;

namespace Microsoft.Teams.Samples.AccountLinking.Bots;

/// <summary>
///  The is an example implementation of a bot and query-based messaging extension that perform account linking.
/// 
/// Unlike the tab, the bot/ME derives the user's identity from the payload and not the token. We can do this because
/// the request is verified as coming from the botframework so it is more trustworthy than an unauthenticated request.
/// </summary>
/// <typeparam name="TDialog">The bot dialog type to use for conversations</typeparam>
public sealed class SampleActivityHandler<TDialog> : TeamsActivityHandler where TDialog : Dialog
{
    private readonly ILogger<SampleActivityHandler<TDialog>> _logger;

    private readonly TDialog _dialog;

    private readonly ConversationState _botState;

    private readonly UserState _userState;

    private readonly GitHubServiceClient _gitHubServiceClient;

    private readonly OAuthTokenProvider _oAuthTokenProvider;

    public SampleActivityHandler(
        ILogger<SampleActivityHandler<TDialog>> logger,
        TDialog dialog,
        OAuthTokenProvider oAuthTokenProvider,
        GitHubServiceClient gitHubServiceClient,
        ConversationState botState,
        UserState userState) : base()
    {
        _logger = logger;
        _gitHubServiceClient = gitHubServiceClient;
        _oAuthTokenProvider = oAuthTokenProvider;
        _dialog = dialog;
        _botState = botState;
        _userState = userState;
    }

    protected override async Task OnMessageActivityAsync(
        ITurnContext<IMessageActivity> turnContext,
        CancellationToken cancellationToken)
    {
        await _dialog.RunAsync(turnContext, _botState.CreateProperty<DialogState>(nameof(DialogState)), cancellationToken);
    }

    public override async Task OnTurnAsync(ITurnContext turnContext, CancellationToken cancellationToken = default)
    {
        await base.OnTurnAsync(turnContext, cancellationToken);

        _logger.LogInformation("Saving state");
        // Save any state changes that might have occurred during the turn.
        await _botState.SaveChangesAsync(turnContext, force: false, cancellationToken: cancellationToken);
        await _userState.SaveChangesAsync(turnContext, force: false, cancellationToken: cancellationToken);
    }

    protected override async Task<MessagingExtensionResponse> OnTeamsMessagingExtensionQueryAsync(
        ITurnContext<IInvokeActivity> turnContext,
        MessagingExtensionQuery query,
        CancellationToken cancellationToken)
    {
        var userId = turnContext.Activity.From.AadObjectId;
        var tenantId = turnContext.Activity.Conversation.TenantId;
        // Attempt to retrieve the github token
        var tokenResult = await _oAuthTokenProvider.GetAccessTokenAsync(tenantId: tenantId, userId: userId);

        if (tokenResult is NeedsConsentResult needsConsentResult)
        {
            _logger.LogInformation("Messaging Extension query with no GitHub token, sending login prompt");
            return new MessagingExtensionResponse
            {
                ComposeExtension = new MessagingExtensionResult
                {
                    Type = "auth",
                    SuggestedActions = new MessagingExtensionSuggestedAction
                    {
                        Actions = new List<CardAction>
                        {
                            new CardAction
                            {
                                Type = ActionTypes.OpenUrl,
                                Value = needsConsentResult.RedirectUri.ToString(),
                                Title = "Please log into GitHub",
                            },
                        },
                    },
                },
            };
        }
        else if (tokenResult is AccessTokenResult accessTokenResult)
        {
            var repos = await _gitHubServiceClient.GetRepositoriesAsync(accessTokenResult.AccessToken);

            return new MessagingExtensionResponse
            {
                ComposeExtension = new MessagingExtensionResult
                {
                    Type = "result",
                    AttachmentLayout = "list",
                    Attachments = repos.Select(r =>
                        new MessagingExtensionAttachment
                        {
                            ContentType = HeroCard.ContentType,
                            Content = new HeroCard { Title = $"{r.Name} ({r.Stars})" },
                            Preview = new HeroCard { Title = $"{r.Name} ({r.Stars})" }.ToAttachment(),
                        }).ToList(),
                },
            };
        }
        // There was an error
        return new MessagingExtensionResponse
        {
        };
    }

    protected override async Task OnTeamsSigninVerifyStateAsync(ITurnContext<IInvokeActivity> turnContext, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Running dialog with signin/verifystate from an Invoke Activity.");

        // The OAuth Prompt needs to see the Invoke Activity in order to complete the login process.

        // Run the Dialog with the new Invoke Activity.
        await _dialog.RunAsync(turnContext, _botState.CreateProperty<DialogState>(nameof(DialogState)), cancellationToken);
    }
}