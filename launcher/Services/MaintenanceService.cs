using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DqxClarity.Launcher.Services;

public enum MaintenanceState { Up, Down, Unknown }

public class MaintenanceService
{
    private static readonly HttpClient Client = new();

    public async Task<(MaintenanceState State, string? Message)> CheckAsync()
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get,
                "https://game.dqx.jp/smgame/gameRequest/mainte/check");
            request.Headers.TryAddWithoutValidation("User-Agent", "Server State Check");
            request.Headers.TryAddWithoutValidation("Cache-Control", "no-cache");

            var response = await Client.SendAsync(request);
            if (response.StatusCode != HttpStatusCode.OK)
                return (MaintenanceState.Unknown, null);

            // Read as plain text and parse by hand rather than ReadFromJsonAsync:
            // the endpoint's maintenance notice puts raw line breaks inside the
            // "text" string (which strict JSON rejects), and it may not send a
            // JSON content type either. Either of those used to throw and land
            // in the catch below as "Status unknown" -- only while the game was
            // in maintenance, since the online response carries no such text.
            var raw = await response.Content.ReadAsStringAsync();
            var (status, message) = ParseBody(raw);

            if (status == null)
                return (MaintenanceState.Unknown, null);
            if (status == "0")
                return (MaintenanceState.Up, null);

            var translated = await TranslateAsync(message);
            return (MaintenanceState.Down, translated);
        }
        catch
        {
            return (MaintenanceState.Unknown, null);
        }
    }

    private static async Task<string?> TranslateAsync(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return text;
        try
        {
            var url = "https://translate.googleapis.com/translate_a/single" +
                      $"?client=gtx&sl=ja&tl=en&dt=t&q={Uri.EscapeDataString(text)}";
            var response = await Client.GetAsync(url);
            var json     = await response.Content.ReadAsStringAsync();

            // Response shape: [[["translated","original",...]], ...]
            var doc = JsonDocument.Parse(json);
            var sb  = new StringBuilder();
            foreach (var segment in doc.RootElement[0].EnumerateArray())
                sb.Append(segment[0].GetString());
            return sb.ToString().Trim();
        }
        catch { return text; }
    }

    // Pulls "status" and "text" out of the response. "status" may be a string
    // ("0" / "1") or a number; "text" is optional. Returns a null status when
    // it can't be found at all.
    private static (string? Status, string? Message) ParseBody(string raw)
    {
        foreach (var candidate in new[] { raw, EscapeControlCharsInStrings(raw) })
        {
            try
            {
                using var doc = JsonDocument.Parse(candidate);
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object) continue;

                string? status = null;
                if (root.TryGetProperty("status", out var s))
                    status = s.ValueKind switch
                    {
                        JsonValueKind.String => s.GetString(),
                        JsonValueKind.Number => s.GetRawText(),
                        _                    => null,
                    };

                string? message = null;
                if (root.TryGetProperty("text", out var t) && t.ValueKind == JsonValueKind.String)
                    message = t.GetString();

                if (status != null) return (status.Trim(), message);
            }
            catch (JsonException) { /* try the next candidate */ }
        }

        // Last resort: not parseable as JSON at all, but the status is still
        // there to read.
        var m = Regex.Match(raw, "\"status\"\\s*:\\s*\"?(?<s>[0-9]+)\"?");
        return m.Success ? (m.Groups["s"].Value, null) : (null, null);
    }

    // JSON strings may not contain raw control characters; the maintenance
    // notice does (it is a multi-line message). Escape them inside string
    // literals so the document parses and the line breaks survive.
    private static string EscapeControlCharsInStrings(string json)
    {
        var sb       = new StringBuilder(json.Length + 16);
        var inString = false;
        var escaped  = false;

        foreach (var c in json)
        {
            if (!inString)
            {
                if (c == '"') inString = true;
                sb.Append(c);
                continue;
            }

            if (escaped)       { escaped = false; sb.Append(c); continue; }
            if (c == '\\')     { escaped = true;  sb.Append(c); continue; }
            if (c == '"')      { inString = false; sb.Append(c); continue; }

            switch (c)
            {
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case < ' ': sb.Append("\\u").Append(((int)c).ToString("x4")); break;
                default:   sb.Append(c); break;
            }
        }
        return sb.ToString();
    }
}
