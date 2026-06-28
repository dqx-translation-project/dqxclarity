namespace DqxClarity.Launcher.Models;

public record LanguagePackCatalogEntry
{
    public string Language { get; init; } = "";
    public string DownloadUrl { get; init; } = "";
    public bool IsDefault { get; init; }

    /// <summary>Human-readable language name (e.g. "English").</summary>
    public string LanguageDisplay => LanguageNames.DisplayName(Language);

    /// <summary>The source filename this catalog entry installs to, e.g. "en.clpk".</summary>
    public string FileName => $"{Language}.clpk";
}

public static class LanguagePackCatalog
{
    // TODO: replace with the real hosted English pack URL
    public const string EnglishPackUrl = "https://TODO.invalid/dqxclarity/english-language-pack.zip";

    public static readonly IReadOnlyList<LanguagePackCatalogEntry> Entries =
    [
        new LanguagePackCatalogEntry
        {
            Language = "en",
            DownloadUrl = EnglishPackUrl,
            IsDefault = true,
        },
    ];

    public static LanguagePackCatalogEntry? Default =>
        Entries.FirstOrDefault(e => e.IsDefault);

    /// <summary>A catalog entry counts as installed when a scanned pack has the same language.</summary>
    public static bool IsInstalled(LanguagePackCatalogEntry entry, IEnumerable<LanguagePack> installed) =>
        installed.Any(pack => string.Equals(pack.Language, entry.Language, StringComparison.OrdinalIgnoreCase));

    /// <summary>Catalog entries that are not yet installed in the given scanned pack list.</summary>
    public static IReadOnlyList<LanguagePackCatalogEntry> NotInstalled(IEnumerable<LanguagePack> installed)
    {
        var packs = installed.ToList();
        return Entries.Where(e => !IsInstalled(e, packs)).ToList();
    }
}
