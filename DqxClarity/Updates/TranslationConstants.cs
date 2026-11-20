using System.Text.RegularExpressions;

namespace DqxClarity.Updates;

internal static class TranslationConstants
{
    public const string CustomTranslationsZipUrl =
        "https://github.com/dqx-translation-project/dqx-custom-translations/archive/refs/heads/main.zip";

    // ── Custom translations repo (language pack option) ─────────────────
    // A language pack can name its own GitHub repo to download in place of
    // dqx-custom-translations (CLPK header field "custom_translations_url").
    // The repo must be laid out like dqx-custom-translations (json/, csv/, ...);
    // it is downloaded the same way, as a zip of its main branch.
    //
    // Accepted forms (trailing "/" and ".git" are fine):
    //   https://github.com/<owner>/<repo>
    //   https://github.com/<repo>                  -> owner dqx-translation-project
    //   https://github.com/<owner>/<repo>/tree/<branch>  -> that branch instead of main
    // Anything else is rejected, and dqxclarity uses the default repo.

    public const string DefaultCustomTranslationsOwner = "dqx-translation-project";
    public const string DefaultCustomTranslationsBranch = "main";

    // GitHub's own rules for owner and repo names are narrower than this; it
    // just keeps anything that isn't a plain name out of the download URL.
    private static readonly Regex RepoNamePart = new("^[A-Za-z0-9._-]+$", RegexOptions.CultureInvariant);

    /// <summary>
    /// Turns a GitHub repo link into the URL of its zip download. False (and null) for a blank
    /// or unrecognised link.
    /// </summary>
    public static bool TryGetCustomTranslationsZipUrl(string? repoUrl, out string? zipUrl)
    {
        zipUrl = null;
        if (string.IsNullOrWhiteSpace(repoUrl)) return false;
        if (!Uri.TryCreate(repoUrl.Trim(), UriKind.Absolute, out var uri)) return false;
        if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) return false;
        if (!uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
            && !uri.Host.Equals("www.github.com", StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)) return false;

        var parts = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => Uri.UnescapeDataString(p)).ToArray();

        string owner, repo, branch = DefaultCustomTranslationsBranch;
        switch (parts.Length)
        {
            case 1:
                owner = DefaultCustomTranslationsOwner;
                repo = parts[0];
                break;
            case 2:
                (owner, repo) = (parts[0], parts[1]);
                break;
            case >= 4 when parts[2] == "tree":
                (owner, repo) = (parts[0], parts[1]);
                branch = string.Join('/', parts[3..]);
                break;
            default:
                return false;
        }

        if (repo.EndsWith(".git", StringComparison.OrdinalIgnoreCase)) repo = repo[..^4];
        if (!RepoNamePart.IsMatch(owner) || !RepoNamePart.IsMatch(repo)) return false;
        if (branch.Split('/').Any(seg => !RepoNamePart.IsMatch(seg))) return false;

        zipUrl = $"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip";
        return true;
    }

    /// <summary>The zip to download for a pack's custom translations link: the link's repo when it
    /// is valid, otherwise the default dqx-custom-translations.</summary>
    public static string ResolveCustomTranslationsZipUrl(string? repoUrl) =>
        TryGetCustomTranslationsZipUrl(repoUrl, out var zip) ? zip! : CustomTranslationsZipUrl;

    public const string MonstersJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/subPackage02Client.json";
    public const string NpcJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/smldt_msg_pkg_NPC_DB.json";
    public const string ItemsJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/subPackage05Client.json";
    public const string KeyItemsJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/subPackage41Client.json";
    public const string QuestsJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/eventTextSysQuestaClient.json";
    public const string CutsceneJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/eventTextSysEventaClient.json";

    public const string CommunityStringApiUrl = "https://community-string-api.ethene.wiki";

    public static readonly (string Url, string Name)[] TranslationFiles =
    {
        (MonstersJsonUrl, "monsters"),
        (NpcJsonUrl,      "npcs"),
        (ItemsJsonUrl,    "items"),
        (KeyItemsJsonUrl, "key_items"),
        (QuestsJsonUrl,   "quests"),
        (CutsceneJsonUrl, "story_names"),
    };
}
