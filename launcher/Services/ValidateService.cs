using System.Text.Json;

namespace DqxClarity.Launcher.Services;

public class ValidateService
{
    public async Task<string> ValidateDeepLKey(string key)
    {
        if (string.IsNullOrEmpty(key))
            throw new Exception("Enter a key before attempting to validate.");

        var url = key.EndsWith(":fx")
            ? "https://api-free.deepl.com/v2/usage"
            : "https://api.deepl.com/v2/usage";

        using var http = new HttpClient();
        http.DefaultRequestHeaders.Add("Authorization", $"DeepL-Auth-Key {key}");
        var resp = await http.GetAsync(url);
        if (!resp.IsSuccessStatusCode)
            throw new Exception($"Key validation failed (HTTP {(int)resp.StatusCode}).");

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        var used  = root.GetProperty("character_count").GetInt64();
        var limit = root.GetProperty("character_limit").GetInt64();

        if (limit == 0) throw new Exception("Unexpected response from DeepL API.");

        var pct = Math.Round(used / (double)limit * 100.0, 2);
        return $"{used}/{limit} characters used ({pct}%).";
    }

    public async Task<string> ValidateGoogleKey(string key)
    {
        if (string.IsNullOrEmpty(key))
            throw new Exception("Enter a key before attempting to validate.");

        var url = $"https://translation.googleapis.com/language/translate/v2?q=a&target=es&source=en&key={key}";
        using var http = new HttpClient();
        var resp = await http.GetAsync(url);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;

        if (root.TryGetProperty("data", out var data) &&
            data.TryGetProperty("translations", out var trans) &&
            trans.ValueKind == JsonValueKind.Array)
            return "Key successfully validated.";

        if (root.TryGetProperty("error", out var err) &&
            err.TryGetProperty("message", out var msg))
            throw new Exception(msg.GetString() ?? "Key validation failed.");

        throw new Exception("Key validation failed.");
    }
}
