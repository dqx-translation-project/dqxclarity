using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;

namespace DqxClarity.Translation.Backends;

// Uses the free mobile translate.google.com endpoint and scrapes the <div class="result-container">.
// No api key. Sequential calls; one phrase per request.
public sealed class GoogleFreeBackend : ITranslationBackend, IDisposable
{
    private const string UserAgent =
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.108 Mobile Safari/537.36";

    private static readonly Regex ResultContainer =
        new(@"<div class=""result-container"">(.*?)</div>", RegexOptions.Singleline | RegexOptions.Compiled);

    private readonly HttpClient _http;

    public GoogleFreeBackend()
    {
        _http = new HttpClient(new HttpClientHandler { AutomaticDecompression = DecompressionMethods.All });
        _http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
    }

    public string Name => "googlefree";
    public Action<string>? OnError { get; set; }

    public IReadOnlyList<string> Translate(IReadOnlyList<string> phrases)
    {
        var results = new List<string>(phrases.Count);
        string? loggedOnce = null;  // dedupe identical errors within one batch
        foreach (var phrase in phrases)
        {
            try
            {
                var encoded = Uri.EscapeDataString(phrase);
                var url = $"https://translate.google.com/m?hl=en&sl=ja&tl=en&q={encoded}";
                var resp = _http.GetAsync(url).GetAwaiter().GetResult();
                if (!resp.IsSuccessStatusCode)
                {
                    var msg = $"http {(int)resp.StatusCode} {resp.ReasonPhrase}";
                    if (loggedOnce != msg) { OnError?.Invoke($"[{Name}] {msg}"); loggedOnce = msg; }
                    results.Add("");
                    continue;
                }
                var body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                var parsed = ParseResult(body);
                if (parsed.Length == 0)
                {
                    const string msg = "scrape returned empty (result-container regex miss — google likely changed the page)";
                    if (loggedOnce != msg) { OnError?.Invoke($"[{Name}] {msg}"); loggedOnce = msg; }
                }
                results.Add(parsed);
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

    private static string ParseResult(string body)
    {
        var m = ResultContainer.Match(body);
        if (!m.Success) return "";
        return WebUtility.HtmlDecode(m.Groups[1].Value.Trim());
    }

    public void Dispose() => _http.Dispose();
}
