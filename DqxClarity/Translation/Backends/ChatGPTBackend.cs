using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace DqxClarity.Translation.Backends;

// Direct HttpClient against OpenAI's
// /v1/chat/completions endpoint. One request per phrase (keeps the system prompt small).
public sealed class ChatGPTBackend : ITranslationBackend, IDisposable
{
    private const string SystemPrompt =
        "You are an expert translator and cultural localization specialist with deep knowledge of " +
        "video game localization. Translate the following Dragon Quest X dialogue from Japanese to " +
        "English. Preserve the original tone, humor, personality, and emotional nuances. Adapt " +
        "idioms and cultural references to resonate naturally with English speakers while maintaining " +
        "the fantasy RPG context. Maintain consistency in character voices and DQX-specific " +
        "terminology. Return only the translated text with no explanation or surrounding quotes.";

    private readonly HttpClient _http;
    private readonly string _model;

    public ChatGPTBackend(string apiKey, string model)
    {
        _model = string.IsNullOrEmpty(model) ? "gpt-4o-mini" : model;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");
    }

    public string Name => "chatgpt";

    public Action<string>? OnError { get; set; }

    public IReadOnlyList<string> Translate(IReadOnlyList<string> phrases)
    {
        var results = new List<string>(phrases.Count);
        string? loggedOnce = null;
        foreach (var phrase in phrases)
        {
            try
            {
                var body = new
                {
                    model = _model,
                    messages = new[]
                    {
                        new { role = "system", content = SystemPrompt },
                        new { role = "user",   content = phrase },
                    },
                    temperature = 0.1,
                };
                var resp = _http.PostAsJsonAsync("https://api.openai.com/v1/chat/completions", body).GetAwaiter().GetResult();
                if (!resp.IsSuccessStatusCode)
                {
                    var errBody = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    var msg = $"http {(int)resp.StatusCode} {resp.ReasonPhrase}: {Truncate(errBody, 200)}";
                    if (loggedOnce != msg) { OnError?.Invoke($"[{Name}] {msg}"); loggedOnce = msg; }
                    results.Add("");
                    continue;
                }
                using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());

                var translated = doc.RootElement.GetProperty("choices")[0]
                    .GetProperty("message").GetProperty("content").GetString() ?? "";
                results.Add(translated.Trim().Trim('"'));
            }
            catch (Exception ex)
            {
                var msg = $"{ex.GetType().Name}: {ex.Message}";
                if (loggedOnce != msg) { OnError?.Invoke($"[{Name}] {msg}"); loggedOnce = msg; }
                results.Add("");
            }
        }
        return results;
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s.Substring(0, max) + "…";

    public void Dispose() => _http.Dispose();
}
