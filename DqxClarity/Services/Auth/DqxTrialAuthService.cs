using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DqxClarity.Services.Auth;

public class TrialAuthResult
{
    public bool    Success        { get; init; }
    public string? SessionId      { get; init; }
    public string? NewDeviceToken { get; init; }
    public string? ErrorMessage   { get; init; }

    public static TrialAuthResult Fail(string msg) =>
        new() { Success = false, ErrorMessage = msg };
}

public class DqxTrialAuthService
{
    private const string AuthUrl =
        "https://dqx-login.square-enix.com/oauth/api/device/auth";

    public async Task<TrialAuthResult> AuthenticateAsync(string deviceId, string deviceToken)
    {
        try
        {
            using var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            };
            using var client = new HttpClient(handler);
            client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent",         "Process Token");
            client.DefaultRequestHeaders.TryAddWithoutValidation("x-cis-device-id",    deviceId);
            client.DefaultRequestHeaders.TryAddWithoutValidation("x-cis-device-token", deviceToken);

            var response = await client.PostAsync(AuthUrl,
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "client_id", "dqx_win" }
                }));

            var body = await response.Content.ReadAsStringAsync();

            TrialAuthResponse? json;
            try
            {
                json = JsonSerializer.Deserialize<TrialAuthResponse>(body);
            }
            catch (JsonException)
            {
                var preview = body.Length > 200 ? body[..200] : body;
                return TrialAuthResult.Fail($"Unexpected server response (HTTP {(int)response.StatusCode}): {preview}");
            }

            if (json == null || json.Status != 0 || json.SessionId == null)
                return TrialAuthResult.Fail($"Trial account authentication failed (status={json?.Status}).");

            return new TrialAuthResult
            {
                Success        = true,
                SessionId      = json.SessionId,
                NewDeviceToken = json.DeviceToken,
            };
        }
        catch (Exception ex)
        {
            return TrialAuthResult.Fail($"Failed to connect to login server: {ex.Message}");
        }
    }

    private class TrialAuthResponse
    {
        [JsonPropertyName("status")]       public int     Status      { get; init; }
        [JsonPropertyName("device_token")] public string? DeviceToken { get; init; }
        [JsonPropertyName("cis_sessid")]   public string? SessionId   { get; init; }
    }
}
