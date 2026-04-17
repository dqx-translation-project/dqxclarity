using System.Diagnostics;
using System.Text.Json;
using DqxClarity.Launcher.Models;
using Microsoft.Win32;

namespace DqxClarity.Launcher.Services;

public class UpdateService
{
    private static HttpClient Http() =>
        new() { DefaultRequestHeaders = { { "User-Agent", "dqxclarity-launcher" } } };

    private static string ExeDir()
    {
        var exe = Environment.ProcessPath ?? throw new Exception("Cannot determine executable path");
        return Path.GetDirectoryName(exe) ?? throw new Exception("Cannot determine executable directory");
    }

    private static string FindAppDir(string exeDir)
    {
        var dir = exeDir;
        for (int i = 0; i < 4; i++)
        {
            if (File.Exists(Path.Combine(dir, "main.py")))
                return Path.GetFullPath(dir);
            dir = Path.Combine(dir, "..");
        }
        return Path.GetFullPath(Path.Combine(exeDir, ".."));
    }

    private static string? FindSystemPython()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Python\PythonCore\3.11-32\InstallPath");
            return key?.GetValue("ExecutablePath") as string;
        }
        catch { return null; }
    }

    public async Task<UpdateInfo?> CheckAsync()
    {
        try
        {
            var dir = ExeDir();
            var appDir = FindAppDir(dir);
            var versionFile = Path.Combine(appDir, "version.update");
            if (!File.Exists(versionFile)) return null;

            var curVer = (await File.ReadAllTextAsync(versionFile)).Trim();

            using var http = Http();
            var resp = await http.GetAsync(
                "https://api.github.com/repos/dqx-translation-project/dqxclarity/releases/latest");
            if (!resp.IsSuccessStatusCode) return null;

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var root = doc.RootElement;
            var tag = root.GetProperty("tag_name").GetString() ?? "";
            var newVer = tag.TrimStart('v');
            var body = root.GetProperty("body").GetString() ?? "";

            if (string.IsNullOrEmpty(newVer) || newVer == curVer) return null;
            return new UpdateInfo(tag, body);
        }
        catch { return null; }
    }

    public async Task RunUpdaterAsync(string tag)
    {
        var dir = ExeDir();
        var appDir = FindAppDir(dir);

        var url = $"https://raw.githubusercontent.com/dqx-translation-project/dqxclarity/refs/tags/{tag}/app/updater.py";
        using var http = Http();
        var bytes = await http.GetByteArrayAsync(url);

        var updaterPath = Path.Combine(appDir, "updater.py");
        await File.WriteAllBytesAsync(updaterPath, bytes);

        var python = FindSystemPython() ?? "python3";
        var psi = new ProcessStartInfo(python, $"\"{updaterPath}\"")
        {
            WorkingDirectory = appDir,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        Process.Start(psi);

        // Exit launcher so updater can replace files freely
        Environment.Exit(0);
    }
}
