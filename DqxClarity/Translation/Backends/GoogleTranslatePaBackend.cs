using System.Net.Http;
using System.Text.Json;

namespace DqxClarity.Translation.Backends;

// Unofficial google translate
// "single" endpoint (client=gtx). No api key. JSON response, segments live at
// data[0][i][0] for joined translation.
public sealed class GoogleTranslatePaBackend : ITranslationBackend, IDisposable
{
    private const string Url = "https://translate.googleapis.com/translate_a/single";
    private readonly HttpClient _http;

    public GoogleTranslatePaBackend()
    {
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
    }

    public string Name => "googletranslatepa";

    public Action<string>? OnError { get; set; }

    public IReadOnlyList<string> Translate(IReadOnlyList<string> phrases)
    {
        var results = new List<string>(phrases.Count);
        string? loggedOnce = null;
        foreach (var phrase in phrases)
        {
            try
            {
                var url = $"{Url}?client=gtx&sl=ja&tl=en&dt=t&q={Uri.EscapeDataString(phrase)}";
                var resp = _http.GetAsync(url).GetAwaiter().GetResult();
                if (!resp.IsSuccessStatusCode)
                {
                    var msg = $"http {(int)resp.StatusCode} {resp.ReasonPhrase}";
                    if (loggedOnce != msg) { OnError?.Invoke($"[{Name}] {msg}"); loggedOnce = msg; }
                    results.Add("");
                    continue;
                }
                using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());

                var sb = new System.Text.StringBuilder();
                foreach (var seg in doc.RootElement[0].EnumerateArray())
                {
                    var first = seg[0];
                    if (first.ValueKind == JsonValueKind.String)
                        sb.Append(first.GetString());
                }
                results.Add(sb.ToString());
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

    public void Dispose() => _http.Dispose();
}
