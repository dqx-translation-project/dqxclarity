using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace DqxClarity.Translation.Backends;

// Works against libretranslate.com
// or any self-hosted instance. api_key is optional — only included when non-empty.
public sealed class LibreTranslateBackend : ITranslationBackend, IDisposable
{
    private readonly HttpClient _http;
    private readonly string _url;
    private readonly string _apiKey;

    public LibreTranslateBackend(string baseUrl, string apiKey)
    {
        _url = baseUrl.TrimEnd('/') + "/translate";
        _apiKey = apiKey ?? "";
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    public string Name => "libretranslate";

    public Action<string>? OnError { get; set; }

    public IReadOnlyList<string> Translate(IReadOnlyList<string> phrases)
    {
        var results = new List<string>(phrases.Count);
        string? loggedOnce = null;
        foreach (var phrase in phrases)
        {
            try
            {
                var form = new Dictionary<string, string>
                {
                    ["q"]      = phrase,
                    ["source"] = "ja",
                    ["target"] = "en",
                    ["format"] = "text",
                };
                if (!string.IsNullOrEmpty(_apiKey)) form["api_key"] = _apiKey;

                var resp = _http.PostAsync(_url, new FormUrlEncodedContent(form)).GetAwaiter().GetResult();
                if (!resp.IsSuccessStatusCode)
                {
                    var errBody = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    var msg = $"http {(int)resp.StatusCode} {resp.ReasonPhrase}: {Truncate(errBody, 200)}";
                    if (loggedOnce != msg) { OnError?.Invoke($"[{Name}] {msg}"); loggedOnce = msg; }
                    results.Add("");
                    continue;
                }
                using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());
                var translated = doc.RootElement.TryGetProperty("translatedText", out var v)
                    ? v.GetString() ?? "" : "";
                results.Add(translated);
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
