using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace DqxClarity.Translation.Backends;

// Direct HttpClient against
// Google Cloud Translate v2 REST API to avoid pulling Google.Cloud.Translation
// as a dep (large SDK with multiple transitive nugets).
public sealed class GoogleBackend : ITranslationBackend, IDisposable
{
    private readonly HttpClient _http;
    private readonly string _apiKey;

    public GoogleBackend(string apiKey)
    {
        _apiKey = apiKey;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
    }

    public string Name => "google";
    public Action<string>? OnError { get; set; }

    public IReadOnlyList<string> Translate(IReadOnlyList<string> phrases)
    {
        try
        {
            // Build the q[]= multi-query, escaping each input.
            var qList = string.Join("&", phrases.Select(p => $"q={Uri.EscapeDataString(p)}"));
            var url = $"https://translation.googleapis.com/language/translate/v2?source=ja&target=en&format=text&key={_apiKey}&{qList}";
            var resp = _http.GetAsync(url).GetAwaiter().GetResult();
            if (!resp.IsSuccessStatusCode)
            {
                var body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                OnError?.Invoke($"[{Name}] http {(int)resp.StatusCode} {resp.ReasonPhrase}: {Truncate(body, 300)}");
                return Array.Empty<string>();
            }
            using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());

            var results = new List<string>(phrases.Count);
            foreach (var t in doc.RootElement.GetProperty("data").GetProperty("translations").EnumerateArray())
                results.Add(t.GetProperty("translatedText").GetString() ?? "");
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
