namespace DqxClarity.Translation;

// Translation backend contract: each backend receives a list of strings, returns
// the same number of strings in order.
//
// Implementations may be stateful (e.g. http session); construct lazily and reuse.
public interface ITranslationBackend
{
    string Name { get; }
    IReadOnlyList<string> Translate(IReadOnlyList<string> phrases);

    // Invoked when a translation request fails. The runtime wires this to the
    // user-visible log so backend errors (bad api key, rate limit, network
    // failure, json shape change) surface instead of being swallowed silently.
    Action<string>? OnError { get; set; }
}
