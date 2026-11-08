namespace DqxClarity.Translation.Backends;

// The "None" translation service: no machine translation at all. Only the
// curated sources (bad_strings, the cached/curated dialog tables, the m00
// dictionaries) are used; a line with no curated entry stays Japanese.
//
// Translator checks for this backend and gives up before doing any work, so
// the callers see "no translation" (an empty result) and neither replace the
// text nor write anything to the cache tables. It is NOT the same as
// EchoBackend, which returns its input unchanged on purpose so tests can
// exercise the rest of the pipeline -- with Echo, the japanese goes through
// the ASCII-only normalisation step and comes out as stray punctuation.
public sealed class NoneBackend : ITranslationBackend
{
    public string Name => "none";
    public Action<string>? OnError { get; set; }
    public IReadOnlyList<string> Translate(IReadOnlyList<string> phrases) => phrases.ToList();
}
