using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace DqxClarity.Translation.Backends;

// Local ollama instance, /api/generate
// endpoint. One request per phrase, prompt-template embedding the source text.
public sealed class OllamaBackend : ITranslationBackend, IDisposable
{
    private const string PromptTemplate =
        "Translate the following Dragon Quest X dialogue from Japanese to English. " +
        "Keep it localized and immersive. Return only the translated text.\n\n\"{0}\"";

    private readonly HttpClient _http;
    private readonly string _url;
    private readonly string _model;

    public OllamaBackend(string baseUrl, string model)
    {
        _url = baseUrl.TrimEnd('/') + "/api/generate";
        _model = string.IsNullOrEmpty(model) ? "llama3" : model;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
    }

    public string Name => "ollama";

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
                    prompt = string.Format(PromptTemplate, phrase),
                    temperature = 0.1,
                    stream = false,
                };
                var resp = _http.PostAsJsonAsync(_url, body).GetAwaiter().GetResult();
                if (!resp.IsSuccessStatusCode)
                {
                    var errBody = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    var msg = $"http {(int)resp.StatusCode} {resp.ReasonPhrase}: {Truncate(errBody, 200)}";
                    if (loggedOnce != msg) { OnError?.Invoke($"[{Name}] {msg}"); loggedOnce = msg; }
                    results.Add("");
                    continue;
                }
                using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());
                var translated = doc.RootElement.TryGetProperty("response", out var r)
                    ? r.GetString() ?? "" : "";
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
