using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DqxClarity.Launcher.Services.Auth;

internal class DqxCookieJar : DelegatingHandler
{
    private readonly string _jarFile;
    private Dictionary<string, List<SerializableCookie>> _cookies = new();

    public DqxCookieJar(HttpMessageHandler inner, string jarFile) : base(inner)
    {
        _jarFile = jarFile;
        Directory.CreateDirectory(Path.GetDirectoryName(jarFile)!);
    }

    public async Task LoadAsync()
    {
        try
        {
            if (!File.Exists(_jarFile)) return;
            await using var stream = File.OpenRead(_jarFile);
            _cookies = await JsonSerializer.DeserializeAsync<Dictionary<string, List<SerializableCookie>>>(stream)
                       ?? new();
        }
        catch { _cookies = new(); }
        Cleanup();
    }

    private async Task SaveAsync()
    {
        Cleanup();
        await using var stream = new FileStream(_jarFile, FileMode.Create);
        await JsonSerializer.SerializeAsync(stream, _cookies);
    }

    private void Cleanup()
    {
        foreach (var key in _cookies.Keys.ToList())
            _cookies[key].RemoveAll(c => c.Expires != DateTime.MinValue && c.Expires <= DateTime.UtcNow);
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Cleanup();
        var uri = request.RequestUri!;

        foreach (var cookie in GetCookies(uri.Host, uri.AbsolutePath))
            request.Headers.TryAddWithoutValidation("Cookie", cookie);

        var response = await base.SendAsync(request, ct);

        if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            foreach (var header in setCookies)
                SetCookie(header, uri.Host);
            await SaveAsync();
        }

        return response;
    }

    private void SetCookie(string header, string domain)
    {
        var cookie = ParseCookie(header, domain);
        if (!_cookies.TryGetValue(domain, out var list))
            _cookies[domain] = list = new();
        list.RemoveAll(c => c.Name == cookie.Name);
        list.Add(cookie);
    }

    private IEnumerable<string> GetCookies(string domain, string path) =>
        _cookies.TryGetValue(domain, out var list)
            ? list.Where(c => path.StartsWith(c.Path) &&
                               (c.Expires == DateTime.MinValue || c.Expires > DateTime.UtcNow))
                   .Select(c => $"{c.Name}={c.Value}")
            : [];

    private static SerializableCookie ParseCookie(string header, string domain)
    {
        var parts = header.Split(';');
        var kv = parts[0].Split('=', 2);

        var flags = parts.Skip(1)
            .Select(p => p.Trim())
            .Where(p => p.Length > 0)
            .Select(p =>
            {
                var fp = p.Split('=', 2);
                return fp.Length == 2
                    ? new KeyValuePair<string, object>(fp[0].Trim(), (object)fp[1])
                    : new KeyValuePair<string, object>(fp[0].Trim(), true);
            })
            .GroupBy(kv2 => kv2.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);

        DateTime expires = DateTime.MinValue;
        if (flags.TryGetValue("Max-Age", out var ma) && ma is string maStr && int.TryParse(maStr, out var secs))
            expires = DateTime.UtcNow.AddSeconds(secs);
        else if (flags.TryGetValue("Expires", out var ex) && ex is string exStr &&
                 DateTime.TryParseExact(exStr, "ddd, dd MMM yyyy HH:mm:ss 'GMT'",
                     null, System.Globalization.DateTimeStyles.AssumeUniversal, out var dt))
            expires = dt;

        return new SerializableCookie
        {
            Name = kv[0].Trim(),
            Value = kv.Length > 1 ? kv[1] : "",
            Domain = flags.TryGetValue("Domain", out var d) && d is string ds ? ds : domain,
            Path = flags.TryGetValue("Path", out var p2) && p2 is string ps ? ps : "/",
            Secure = flags.ContainsKey("Secure"),
            HttpOnly = flags.ContainsKey("HttpOnly"),
            Expires = expires,
        };
    }

    private record SerializableCookie
    {
        public string Name { get; init; } = "";
        public string Value { get; init; } = "";
        public string Domain { get; init; } = "";
        public string Path { get; init; } = "/";
        public bool Secure { get; init; }
        public bool HttpOnly { get; init; }
        public DateTime Expires { get; init; } = DateTime.MinValue;
    }
}
