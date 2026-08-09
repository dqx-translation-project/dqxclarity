using System.Net.Http;
using System.Text.Json;

namespace DqxClarity.Translation.Backends;

// The unofficial android-app endpoint;
// session-stable ucid that rolls over every UcidTtl seconds.
public sealed class YandexBackend : ITranslationBackend, IDisposable
{
    private const string Url = "https://translate.yandex.net/api/v1/tr.json/translate";
    private const string UserAgent = "ru.yandex.translate/3.20.2024";
    private static readonly TimeSpan UcidTtl = TimeSpan.FromSeconds(360);

    private readonly HttpClient _http;
    private string? _ucid;
    private DateTime _ucidExpires;

    public YandexBackend()
    {
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        _http.DefaultRequestHeaders.Add("User-Agent", UserAgent);
    }

    public string Name => "yandex";

    private string GetUcid()
    {
        if (_ucid != null && DateTime.UtcNow < _ucidExpires) return _ucid;
        _ucid = Guid.NewGuid().ToString("N");
        _ucidExpires = DateTime.UtcNow + UcidTtl;
        return _ucid;
    }

    public Action<string>? OnError { get; set; }

    public IReadOnlyList<string> Translate(IReadOnlyList<string> phrases)
    {
        var results = new List<string>(phrases.Count);
        var ucid = GetUcid();
        string? loggedOnce = null;
        foreach (var phrase in phrases)
        {
            try
            {
                var url = $"{Url}?ucid={ucid}&srv=android&format=text";
                var form = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("text", phrase),
                    new KeyValuePair<string, string>("lang", "ja-en"),
                });
                var resp = _http.PostAsync(url, form).GetAwaiter().GetResult();
                if (!resp.IsSuccessStatusCode)
                {
                    var msg = $"http {(int)resp.StatusCode} {resp.ReasonPhrase}";
                    if (loggedOnce != msg) { OnError?.Invoke($"[{Name}] {msg}"); loggedOnce = msg; }
                    results.Add("");
                    continue;
                }
                using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());
                if (doc.RootElement.TryGetProperty("code", out var code) && code.GetInt32() == 200
                    && doc.RootElement.TryGetProperty("text", out var arr) && arr.GetArrayLength() > 0)
                {
                    results.Add(arr[0].GetString() ?? "");
                }
                else
                {
                    var codeVal = doc.RootElement.TryGetProperty("code", out var c) ? c.GetInt32().ToString() : "?";
                    var msg = $"api returned code={codeVal}";
                    if (loggedOnce != msg) { OnError?.Invoke($"[{Name}] {msg}"); loggedOnce = msg; }
                    results.Add("");
                }
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
