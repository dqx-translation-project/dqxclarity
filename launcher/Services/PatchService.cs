using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace DqxClarity.Launcher.Services;

public class PatchService
{
    public event Action<long, long>? Progress; // downloaded, total

    private HttpClient Http() =>
        new() { DefaultRequestHeaders = { { "User-Agent", "dqxclarity-launcher" } } };

    private static bool IsDqxRunning()
    {
        try
        {
            var psi = new ProcessStartInfo("tasklist", "/FI \"IMAGENAME eq DQXGame.exe\" /NH /FO CSV")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            var proc = Process.Start(psi);
            var output = proc?.StandardOutput.ReadToEnd() ?? "";
            proc?.WaitForExit();
            return output.Contains("DQXGame.exe", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    [DllImport("Shell32.dll")]
    private static extern int IsUserAnAdmin();

    private static bool IsAdmin()
    {
        try { return IsUserAnAdmin() != 0; }
        catch { return false; }
    }

    private async Task<string> LatestReleaseUrl(HttpClient http, string repo, string assetName)
    {
        var resp = await http.GetAsync($"https://api.github.com/repos/{repo}/releases/latest");
        resp.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var assets = doc.RootElement.GetProperty("assets");
        foreach (var asset in assets.EnumerateArray())
        {
            if (asset.GetProperty("name").GetString() == assetName)
                return asset.GetProperty("browser_download_url").GetString()
                    ?? throw new Exception($"No download URL for {assetName}");
        }
        throw new Exception($"Asset '{assetName}' not found in the latest release of {repo}");
    }

    private async Task<byte[]> FetchWithProgress(HttpClient http, string url)
    {
        var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
        resp.EnsureSuccessStatusCode();

        var total = resp.Content.Headers.ContentLength ?? 0;
        using var stream = await resp.Content.ReadAsStreamAsync();
        var buffer = new byte[81920];
        var data = new List<byte>();
        long downloaded = 0;

        int read;
        while ((read = await stream.ReadAsync(buffer)) > 0)
        {
            data.AddRange(buffer[..read]);
            downloaded += read;
            Progress?.Invoke(downloaded, total);
        }
        return [.. data];
    }

    public async Task PatchLauncher(string installDir)
    {
        using var http = Http();
        var url = await LatestReleaseUrl(http, "dqx-translation-project/dqx_en_launcher", "DQXLauncher.exe");
        var bytes = await FetchWithProgress(http, url);
        await File.WriteAllBytesAsync(Path.Combine(installDir, "Boot", "DQXLauncher.exe"), bytes);
    }

    public async Task RestoreLauncher(string installDir)
    {
        using var http = Http();
        var bytes = await FetchWithProgress(http,
            "https://github.com/dqx-translation-project/dqx_en_launcher/raw/refs/heads/main/assets/DQXLauncher.exe");
        await File.WriteAllBytesAsync(Path.Combine(installDir, "Boot", "DQXLauncher.exe"), bytes);
    }

    public async Task PatchConfig(string installDir)
    {
        using var http = Http();
        var url = await LatestReleaseUrl(http, "dqx-translation-project/dqx_en_config", "DQXConfig.exe");
        var bytes = await FetchWithProgress(http, url);
        await File.WriteAllBytesAsync(Path.Combine(installDir, "Game", "DQXConfig.exe"), bytes);
    }

    public async Task RestoreConfig(string installDir)
    {
        using var http = Http();
        var bytes = await FetchWithProgress(http,
            "https://github.com/dqx-translation-project/dqx_en_config/raw/refs/heads/main/assets/DQXConfig.exe");
        await File.WriteAllBytesAsync(Path.Combine(installDir, "Game", "DQXConfig.exe"), bytes);
    }

    public async Task PatchGameFiles(string installDir)
    {
        if (!IsAdmin())
            throw new Exception(
                "dqxclarity must be running as an administrator to apply game files.\nPlease re-launch as an administrator and try again.");
        if (IsDqxRunning())
            throw new Exception("Please close DQX before patching game files.");

        var dataDir = Path.Combine(installDir, "Game", "Content", "Data");
        using var http = Http();

        var dat1 = await FetchWithProgress(http,
            "https://github.com/dqx-translation-project/dqxclarity/releases/latest/download/data00000000.win32.dat1");
        await File.WriteAllBytesAsync(Path.Combine(dataDir, "data00000000.win32.dat1"), dat1);

        var idx = await FetchWithProgress(http,
            "https://github.com/dqx-translation-project/dqxclarity/releases/latest/download/data00000000.win32.idx");
        await File.WriteAllBytesAsync(Path.Combine(dataDir, "data00000000.win32.idx"), idx);
    }
}
