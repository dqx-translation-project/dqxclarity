namespace DqxClarity.Translation.Backends;

// Deterministic backend that returns input phrases unchanged. Used to exercise
// the surrounding pipeline (placeholder swap, glossary, wrap, br-inject) in
// tests without making real api calls.
public sealed class EchoBackend : ITranslationBackend
{
    public string Name => "echo";
    public Action<string>? OnError { get; set; }
    public IReadOnlyList<string> Translate(IReadOnlyList<string> phrases) => phrases.ToList();
}
