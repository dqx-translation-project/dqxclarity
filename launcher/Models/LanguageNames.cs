using System.Globalization;

namespace DqxClarity.Launcher.Models;

/// <summary>Maps a language code (e.g. "en") to a human-readable name (e.g. "English") using the
/// .NET/ICU culture data — no hardcoded table. Falls back to the raw code for unknown codes.</summary>
public static class LanguageNames
{
    public static string DisplayName(string? code)
    {
        if (string.IsNullOrWhiteSpace(code)) return "";
        try { return CultureInfo.GetCultureInfo(code).EnglishName; }
        catch (CultureNotFoundException) { return code; }
    }
}
