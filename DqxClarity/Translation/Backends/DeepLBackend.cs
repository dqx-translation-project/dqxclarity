using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace DqxClarity.Translation.Backends;

// Direct HttpClient against DeepL's
// v2 /translate endpoint to avoid pulling the official SDK as a dep.
// API key format determines the host: free keys end with ":fx" -> api-free.deepl.com.
public sealed class DeepLBackend : ITranslationBackend, IDisposable
{
    // Custom instructions passed to the model alongside each request.
    private static readonly string[] CustomInstructions =
    {
        "You are an expert translator and cultural localization specialist with deep knowledge of video game localization. Preserve the original tone, humor, personality, and emotional nuances of the dialogue, considering the unique style and atmosphere of Dragon Quest X.",
        "Adapt idioms, cultural references, and wordplay to resonate naturally with native English speakers while maintaining the fantasy RPG context. Avoid the overuse of profanity. Don't use the same word over and over.",
        "Maintain consistency in character voices, terminology, and naming conventions specific to Dragon Quest X throughout the translation.",
        "Avoid literal translations that may lose the original intent or impact, especially for game-specific terms or lore elements. Any text that's returned should only include ASCII character codes 33 through 127.",
        "Ensure the translation flows naturally and reads as if it were originally written in English, while staying true to the game's narrative style.",
        "Consider the context and subtext of the dialogue, including any references to the game's lore, world, or ongoing storylines.",
        "If a word, phrase, or name has been translated in a specific way, maintain that translation consistently unless the context demands otherwise, respecting established localization choices for Dragon Quest X.",
        "Pay attention to formal/informal speech patterns and adjust accordingly for the target language and cultural norms, considering the speaker's role and status within the game world.",
        "Be mindful of character limits or text box constraints that may be present in the game, adapting the translation to fit if necessary.",
        "Preserve any game-specific jargon, spell names, or technical terms according to the official localization guidelines for Dragon Quest X.",
    };

    private readonly HttpClient _http;
    private readonly string _endpoint;

    public DeepLBackend(string apiKey)
    {
        _endpoint = apiKey.EndsWith(":fx", StringComparison.Ordinal)
            ? "https://api-free.deepl.com/v2/translate"
            : "https://api.deepl.com/v2/translate";
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        _http.DefaultRequestHeaders.Add("Authorization", $"DeepL-Auth-Key {apiKey}");
    }

    public string Name => "deepl";
    public Action<string>? OnError { get; set; }

    public IReadOnlyList<string> Translate(IReadOnlyList<string> phrases)
    {
        try
        {
            var body = new
            {
                text = phrases,
                source_lang = "ja",
                target_lang = "en-us",
                preserve_formatting = true,
                model_type = "prefer_quality_optimized",
                custom_instructions = CustomInstructions,
            };
            var resp = _http.PostAsJsonAsync(_endpoint, body).GetAwaiter().GetResult();
            if (!resp.IsSuccessStatusCode)
            {
                var errBody = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                OnError?.Invoke($"[{Name}] http {(int)resp.StatusCode} {resp.ReasonPhrase}: {Truncate(errBody, 300)}");
                return Array.Empty<string>();
            }
            using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());

            var results = new List<string>(phrases.Count);
            foreach (var t in doc.RootElement.GetProperty("translations").EnumerateArray())
                results.Add(t.GetProperty("text").GetString() ?? "");
            return results;
        }
        catch (Exception ex)
        {
            OnError?.Invoke($"[{Name}] {ex.GetType().Name}: {ex.Message}");
            return Array.Empty<string>();
        }
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s.Substring(0, max) + "…";

    public void Dispose() => _http.Dispose();
}
