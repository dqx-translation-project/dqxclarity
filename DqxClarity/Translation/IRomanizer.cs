namespace DqxClarity.Translation;

// Japanese-text-to-romaji conversion. The real implementation is a p/invoke
// wrapper around the bundled wanakana.dll (rust cdylib) that lands in phase e.
// Until then a NullRomanizer pass-through keeps the packet code building.
public interface IRomanizer
{
    string ToRomaji(string text, int maxLength = 10);
}

public sealed class NullRomanizer : IRomanizer
{
    public string ToRomaji(string text, int maxLength = 10) =>
        text.Length <= maxLength ? text : text[..maxLength];
}
