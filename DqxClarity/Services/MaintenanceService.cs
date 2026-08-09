using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DqxClarity.Services;

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

            var body = await response.Content.ReadFromJsonAsync<MaintenanceResponse>();
            if (body?.Status == "0")
                return (MaintenanceState.Up, null);

            var translated = await TranslateAsync(body?.Message);
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

    private record MaintenanceResponse
    {
        [JsonPropertyName("status")] public required string Status  { get; init; }
        [JsonPropertyName("text")]   public required string Message { get; init; }
    }
}
