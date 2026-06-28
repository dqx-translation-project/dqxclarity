using System.IO;

namespace DqxClarity.Launcher.Models;

public record LanguagePackCatalogEntry
{
    public string Name { get; init; } = "";
    public string Language { get; init; } = "";
    public string DownloadUrl { get; init; } = "";
    public bool IsDefault { get; init; }

    /// <summary>The source-zip filename this catalog entry installs to, e.g. "English.zip".</summary>
    public string ZipFileName => $"{Name}.zip";
}

public static class LanguagePackCatalog
{
    // TODO: replace with the real hosted English pack URL
    public const string EnglishPackUrl = "https://TODO.invalid/dqxclarity/english-language-pack.zip";

    public static readonly IReadOnlyList<LanguagePackCatalogEntry> Entries =
    [
        new LanguagePackCatalogEntry
        {
            Name = "English",
            Language = "en",
            DownloadUrl = EnglishPackUrl,
            IsDefault = true,
        },
    ];

    public static LanguagePackCatalogEntry? Default =>
        Entries.FirstOrDefault(e => e.IsDefault);

    /// <summary>
    /// A catalog entry counts as installed when a scanned pack's source zip filename matches
    /// the entry's derived filename (e.g. "English.zip") OR the pack's manifest Name matches.
    /// </summary>
    public static bool IsInstalled(LanguagePackCatalogEntry entry, IEnumerable<LanguagePack> installed) =>
        installed.Any(pack =>
            string.Equals(Path.GetFileName(pack.Path), entry.ZipFileName, StringComparison.OrdinalIgnoreCase)
            || string.Equals(pack.Name, entry.Name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Catalog entries that are not yet installed in the given scanned pack list.</summary>
    public static IReadOnlyList<LanguagePackCatalogEntry> NotInstalled(IEnumerable<LanguagePack> installed)
    {
        var packs = installed.ToList();
        return Entries.Where(e => !IsInstalled(e, packs)).ToList();
    }
}
