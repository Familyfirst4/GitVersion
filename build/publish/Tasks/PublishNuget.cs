using System.Net.Http.Headers;
using System.Text.Json;
using Cake.Common.Tools.DotNet.NuGet.Push;
using Common.Utilities;

namespace Publish.Tasks;

[TaskName(nameof(PublishNuget))]
[TaskDescription("Publish nuget packages")]
[IsDependentOn(typeof(PublishNugetInternal))]
public class PublishNuget : FrostingTask<BuildContext>;

[TaskName(nameof(PublishNugetInternal))]
[TaskDescription("Publish nuget packages")]
public class PublishNugetInternal : AsyncFrostingTask<BuildContext>
{
    public override bool ShouldRun(BuildContext context)
    {
        var shouldRun = true;
        shouldRun &= context.ShouldRun(context.IsGitHubActionsBuild, $"{nameof(PublishNuget)} works only on GitHub Actions.");
        shouldRun &= context.ShouldRun(context.IsStableRelease || context.IsTaggedPreRelease || context.IsInternalPreRelease, $"{nameof(PublishNuget)} works only for releases.");

        return shouldRun;
    }

    public override async Task RunAsync(BuildContext context)
    {
        // publish to github packages for commits on main and on original repo
        if (context.IsInternalPreRelease)
        {
            context.StartGroup("Publishing to GitHub Packages");
            var apiKey = context.Credentials?.GitHub?.Token;
            if (string.IsNullOrEmpty(apiKey))
            {
                throw new InvalidOperationException("Could not resolve NuGet GitHub Packages API key.");
            }
            PublishToNugetRepo(context, apiKey, Constants.GithubPackagesUrl);
            context.EndGroup();
        }

        var nugetApiKey = await GetNugetApiKey(context);
        if (string.IsNullOrEmpty(nugetApiKey))
        {
            context.Warning("Could not retrieve NuGet API key.");
        }
        else
        {
            context.Information("Successfully retrieved NuGet API key via OIDC.");
        }
        // publish to nuget.org for tagged releases
        if (context.IsStableRelease || context.IsTaggedPreRelease)
        {
            context.StartGroup("Publishing to Nuget.org");
            var apiKey = context.Credentials?.Nuget?.ApiKey;
            if (string.IsNullOrEmpty(apiKey))
            {
                throw new InvalidOperationException("Could not resolve NuGet org API key.");
            }
            PublishToNugetRepo(context, apiKey, Constants.NugetOrgUrl);
            context.EndGroup();
            var url = new Uri(
                "https://run-actions-2-azure-eastus.actions.githubusercontent.com/68//idtoken/71084348-96ba-41e6-b690-47fc84f192c3/30514149-640b-5df8-9fad-53dc9469f7f8?api-version=2.0&audience=https%3A%2F%2Fwww.nuget.org");
        }
    }
    private static void PublishToNugetRepo(BuildContext context, string apiKey, string apiUrl)
    {
        ArgumentNullException.ThrowIfNull(context.Version);
        var nugetVersion = context.Version.NugetVersion;
        foreach (var (packageName, filePath, _) in context.Packages.Where(x => !x.IsChocoPackage))
        {
            context.Information($"Package {packageName}, version {nugetVersion} is being published.");
            context.DotNetNuGetPush(filePath.FullPath, new DotNetNuGetPushSettings
            {
                ApiKey = apiKey,
                Source = apiUrl,
                SkipDuplicate = true
            });
        }
    }

    private static async Task<string?> GetNugetApiKey(BuildContext context)
    {
        try
        {
            const string nugetUsername = "gittoolsbot";
            const string nugetTokenServiceUrl = "https://www.nuget.org/api/v2/token";
            const string nugetAudience = "https://www.nuget.org";

            var oidcRequestToken = context.Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
            var oidcRequestUrl = context.Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL");

            if (string.IsNullOrEmpty(oidcRequestToken) || string.IsNullOrEmpty(oidcRequestUrl))
                throw new InvalidOperationException("Missing GitHub OIDC request environment variables.");

            var tokenUrl = $"{oidcRequestUrl}&audience={Uri.EscapeDataString(nugetAudience)}";
            context.Information($"Requesting GitHub OIDC token from: {tokenUrl}");

            using var http = new HttpClient();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", oidcRequestToken);
            var tokenResp = await http.GetAsync(tokenUrl);
            var tokenBody = await tokenResp.Content.ReadAsStringAsync();

            if (!tokenResp.IsSuccessStatusCode)
                throw new Exception("Failed to retrieve OIDC token from GitHub.");

            using var tokenDoc = JsonDocument.Parse(tokenBody);
            if (!tokenDoc.RootElement.TryGetProperty("value", out var valueElem) || valueElem.ValueKind != JsonValueKind.String)
                throw new Exception("Failed to retrieve OIDC token from GitHub.");

            var oidcToken = valueElem.GetString();

            var requestBody = JsonSerializer.Serialize(new { username = nugetUsername, tokenType = "ApiKey" });

            using var tokenServiceHttp = new HttpClient();
            tokenServiceHttp.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", oidcToken);
            tokenServiceHttp.DefaultRequestHeaders.UserAgent.ParseAdd("nuget/login-action");
            var content = new StringContent(requestBody, Encoding.UTF8, "application/json");
            var exchangeResp = await tokenServiceHttp.PostAsync(nugetTokenServiceUrl, content);
            var exchangeBody = await exchangeResp.Content.ReadAsStringAsync();

            if (!exchangeResp.IsSuccessStatusCode)
            {
                var errorMessage = $"Token exchange failed ({(int)exchangeResp.StatusCode})";
                try
                {
                    using var errDoc = JsonDocument.Parse(exchangeBody);
                    errorMessage +=
                        errDoc.RootElement.TryGetProperty("error", out var errProp) &&
                        errProp.ValueKind == JsonValueKind.String
                            ? $": {errProp.GetString()}"
                            : $": {exchangeBody}";
                }
                catch
                {
                    errorMessage += $": {exchangeBody}";
                }
                throw new Exception(errorMessage);
            }

            using var respDoc = JsonDocument.Parse(exchangeBody);
            if (!respDoc.RootElement.TryGetProperty("apiKey", out var apiKeyProp) || apiKeyProp.ValueKind != JsonValueKind.String)
                throw new Exception("Response did not contain \"apiKey\".");

            var apiKey = apiKeyProp.GetString();
            context.Information($"Successfully exchanged OIDC token for NuGet API key.");
            return apiKey;
        }
        catch (Exception ex)
        {
            context.Error($"Failed to retrieve NuGet API key: {ex.Message}");
            return null;
        }
    }
}
