using DqxClarity.Data;

namespace DqxClarity.Translation;

// Loads the glossary from clarity_dialog.db once and applies it to text.
// Longest-first ordering by utf-8 byte length of the ja key (truncated to first
// comma if present) is critical — short keys would otherwise consume substrings
// of long keys before the long keys ever match.
public sealed class GlossaryCache
{
    private readonly List<KeyValuePair<string, string>> _entries;

    private GlossaryCache(List<KeyValuePair<string, string>> entries)
    {
        _entries = entries;
    }

    public static GlossaryCache Load(ClarityDb db) =>
        new(db.LoadGlossarySortedLongestFirst());

    // Each match wraps the english replacement in single spaces to avoid two adjacent
    // replacements colliding, then collapses any resulting double space.
    public string Apply(string text)
    {
        foreach (var (ja, en) in _entries)
            text = text.Replace(ja, $" {en} ");
        text = text.Replace("  ", " ");
        return text.TrimStart();
    }
}
