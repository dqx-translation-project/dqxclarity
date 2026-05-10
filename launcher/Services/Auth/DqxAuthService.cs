using System.Net;
using System.Security.Cryptography;
using System.Text;
using HtmlAgilityPack;

namespace DqxClarity.Launcher.Services.Auth;

public enum AuthStatus
{
    NeedsUsernamePassword,
    NeedsOtp,
    Success,
    Error,
}

public class AuthResult
{
    public AuthStatus Status { get; init; }
    public string? SessionId { get; init; }
    public string? Username { get; init; }
    public string? ErrorMessage { get; init; }

    public static AuthResult Fail(string message) =>
        new() { Status = AuthStatus.Error, ErrorMessage = message };
    public static AuthResult NeedsUsernamePassword() =>
        new() { Status = AuthStatus.NeedsUsernamePassword };
    public static AuthResult NeedsOtp(string? username) =>
        new() { Status = AuthStatus.NeedsOtp, Username = username };
}

public class DqxAuthService
{
    private const string LoginUrl =
        "https://dqx-login.square-enix.com/oauth/sp/sso/dqxwin/login" +
        "?client_id=dqx_win" +
        "&redirect_uri=https%3a%2f%2fdqx%2dlogin%2esquare%2denix%2ecom%2f" +
        "&response_type=code";

    private static readonly string CacheDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                     "dqxclarity", "cache");

    private HttpClient? _client;
    private DqxWebForm? _pendingForm;
    private string? _pendingUsername;

    /// <summary>
    /// Send dqxmode=2 with the stored token to retrieve the account's username from the server.
    /// Returns null if the token is invalid, expired, or the request fails.
    /// </summary>
    public async Task<string?> LookupUsernameAsync(string token)
    {
        try
        {
            _client = await BuildClientAsync("saved-player");
            var form = await FetchLoginFormAsync(new() { { "dqxmode", "2" }, { "id", token } });
            return form?.Fields.TryGetValue("sqexid", out var u) == true && !string.IsNullOrEmpty(u)
                ? u : null;
        }
        catch { return null; }
    }

    /// <summary>Start a new-account login (no saved token). Returns NeedsUsernamePassword.</summary>
    public async Task<AuthResult> BeginNewLoginAsync()
    {
        _client = await BuildClientAsync("new-player");
        _pendingForm = await FetchLoginFormAsync(new() { { "dqxmode", "1" } });
        if (_pendingForm is null)
            return AuthResult.Fail("Failed to load login form");
        _pendingUsername = null;
        return AuthResult.NeedsUsernamePassword();
    }

    /// <summary>Submit username + password after BeginNewLoginAsync.</summary>
    public async Task<AuthResult> SubmitCredentialsAsync(string username, string password)
    {
        if (_client is null || _pendingForm is null)
            return AuthResult.Fail("No active login session");
        _pendingForm.Fields["sqexid"] = username;
        _pendingForm.Fields["password"] = password;
        _pendingUsername = username;
        return await SubmitFormAsync(username, password);
    }

    /// <summary>Submit a one-time password when AuthStatus.NeedsOtp is returned.</summary>
    public async Task<AuthResult> SubmitOtpAsync(string otp)
    {
        if (_client is null || _pendingForm is null)
            return AuthResult.Fail("No active login session");

        // The OTP field name observed in the wild is "oneTimePassword".
        // If the field doesn't exist, fall back to the first non-hidden field we find.
        if (!_pendingForm.Fields.ContainsKey("oneTimePassword"))
        {
            var otpField = _pendingForm.Fields.Keys
                .FirstOrDefault(k => k.Contains("otp", StringComparison.OrdinalIgnoreCase)
                                  || k.Contains("onetime", StringComparison.OrdinalIgnoreCase));
            if (otpField is not null)
                _pendingForm.Fields[otpField] = otp;
        }
        else
        {
            _pendingForm.Fields["oneTimePassword"] = otp;
        }

        return await SubmitFormAsync(_pendingUsername, null);
    }

    private async Task<AuthResult> SubmitFormAsync(string? username, string? password)
    {
        var request = new HttpRequestMessage(_pendingForm!.Method, _pendingForm.Action)
        {
            Content = new FormUrlEncodedContent(_pendingForm.Fields)
        };
        var httpResponse = await _client!.SendAsync(request);
        var response = await DqxLoginResponse.ParseAsync(httpResponse);

        if (response.ErrorMessage is not null)
        {
            _pendingForm = response.Form ?? _pendingForm;
            var message = response.IsOtpForm
                ? "Invalid one-time password. Please check your authenticator app and try again."
                : response.ErrorMessage;
            return AuthResult.Fail(message);
        }

        if (response.SessionId is not null)
        {
            return new AuthResult
            {
                Status = AuthStatus.Success,
                SessionId = response.SessionId,
                Username = username,
            };
        }

        // No session ID and no error — likely OTP step
        if (response.Form is not null)
        {
            _pendingForm = response.Form;
            return AuthResult.NeedsOtp(username);
        }

        return AuthResult.Fail("Login failed — unexpected server response");
    }

    private async Task<DqxWebForm?> FetchLoginFormAsync(Dictionary<string, string> payload)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Post, LoginUrl)
            {
                Content = new FormUrlEncodedContent(payload)
            };
            var response = await _client!.SendAsync(request);
            var doc = new HtmlDocument();
            doc.LoadHtml(await response.Content.ReadAsStringAsync());
            var form = doc.DocumentNode.SelectSingleNode("//form[@name='mainForm']");
            if (form is null) return null;
            return DqxWebForm.Parse(form, new Uri(LoginUrl));
        }
        catch { return null; }
    }

    private static async Task<HttpClient> BuildClientAsync(string jarName)
    {
        var jarFile = Path.Combine(CacheDir, $"{jarName}.cookies.json");
        var inner = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        };
        var jar = new DqxCookieJar(inner, jarFile);
        await jar.LoadAsync();

        var client = new HttpClient(jar);
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cache-Control", "max-age=0");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Connection", "Keep-Alive");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept",
            "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Language", "en-US");
        client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent",
            $"SQEXAuthor/2.0.0(Windows 6.2; ja-jp; {MakeComputerId()})");
        return client;
    }

    private static string MakeComputerId()
    {
        var hashInput = Environment.MachineName + Environment.UserName +
                        Environment.OSVersion + Environment.ProcessorCount;
        using var sha1 = SHA1.Create();
        var bytes = new byte[5];
        Array.Copy(sha1.ComputeHash(Encoding.Unicode.GetBytes(hashInput)), 0, bytes, 1, 4);
        bytes[0] = (byte)-(bytes[1] + bytes[2] + bytes[3] + bytes[4]);
        return BitConverter.ToString(bytes).Replace("-", "").ToLower();
    }
}
