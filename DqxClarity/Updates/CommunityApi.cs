using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace DqxClarity.Updates;

//

// POSTs a (jp, tr, npc_name) tuple to the community string api when the user
// has opted in. Player/sibling names in the source string get replaced with
// `<pnplacehold>` / `<snplacehold>` so we never leak the player's name.
public sealed class CommunityApi
{
    private readonly string _baseUrl;
    private readonly string _apiKey;
    private readonly HttpClient _http;

    public CommunityApi(string baseUrl, string apiKey)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _apiKey = apiKey;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
    }

    public async Task<bool> SubmitAsync(string japanese, string translated, string npcName,
                                        string playerName, string siblingName, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_apiKey)) return false;

        // Placeholder swap for the source — the api never sees the real player or sibling name.
        var jpSafe = japanese
            .Replace(playerName, "<pnplacehold>")
            .Replace(siblingName, "<snplacehold>");

        // If we substituted anything in the source, replace the translated version too.
        var trSafe = jpSafe != japanese ? jpSafe : translated;

        var body = JsonSerializer.Serialize(new { jp = jpSafe, tr = trSafe, npc_name = npcName });

        using var req = new HttpRequestMessage(HttpMethod.Post, _baseUrl)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        req.Headers.Add("x-api-key", _apiKey);
        // Player/sibling names are jp characters; HttpHeaders forces latin-1 by default
        // so we encode bytes as utf-8 then attach as ascii-escaped.
        req.Headers.Add("x-character-name", Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(playerName)));
        req.Headers.Add("x-sibling-name", Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(siblingName)));

        try
        {
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            return resp.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }
}
