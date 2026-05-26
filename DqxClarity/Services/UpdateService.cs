using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Text.Json;
using DqxClarity.Models;

namespace DqxClarity.Services;

public class UpdateService
{
    private static HttpClient Http() =>
        new() { DefaultRequestHeaders = { { "User-Agent", "dqxclarity-launcher" } } };

    private static string ExeDir()
    {
        var exe = Environment.ProcessPath ?? throw new Exception("Cannot determine executable path");
        return Path.GetDirectoryName(exe) ?? throw new Exception("Cannot determine executable directory");
    }

    private static string AssemblyVersion()
    {
        var v = Assembly.GetEntryAssembly()?.GetName().Version;
        return v is null ? "0.0.0" : $"{v.Major}.{v.Minor}.{v.Build}";
    }

    public async Task<UpdateInfo?> CheckAsync()
    {
        try
        {
            var curVer = AssemblyVersion();

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

    public async Task RunUpdaterAsync(string tag, IProgress<(long received, long total)>? progress = null)
    {
        var exeDir = ExeDir();
        var currentExe = Environment.ProcessPath!;
        var bakPath = currentExe + ".bak";
        var tempZip = Path.Combine(Path.GetTempPath(), "dqxclarity_update.zip");

        try
        {
            var url = $"https://github.com/dqx-translation-project/dqxclarity/releases/download/{tag}/dqxclarity.zip";
            using var http = Http();
            using (var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead))
            {
                resp.EnsureSuccessStatusCode();
                var total = resp.Content.Headers.ContentLength ?? -1L;
                using var stream = await resp.Content.ReadAsStreamAsync();
                using var fs = new FileStream(tempZip, FileMode.Create, FileAccess.Write, FileShare.None);
                var buf = new byte[81920];
                long received = 0;
                int read;
                while ((read = await stream.ReadAsync(buf)) > 0)
                {
                    await fs.WriteAsync(buf.AsMemory(0, read));
                    received += read;
                    progress?.Report((received, total));
                }
            }

            var exeDirSlash = exeDir + Path.DirectorySeparatorChar;
            var preserved = new[]
            {
                Path.GetFullPath(Path.Combine(exeDir, "misc_files")) + Path.DirectorySeparatorChar,
                Path.GetFullPath(Path.Combine(exeDir, "logs")) + Path.DirectorySeparatorChar,
                Path.GetFullPath(Path.Combine(exeDir, "user_settings.ini")),
            };

            using (var archive = ZipFile.OpenRead(tempZip))
            {
                // Validate entries and build extraction list (zip-slip protection)
                var entries = new List<(ZipArchiveEntry entry, string dest)>();
                foreach (var entry in archive.Entries)
                {
                    var rel = entry.FullName.StartsWith("dqxclarity/", StringComparison.OrdinalIgnoreCase)
                        ? entry.FullName["dqxclarity/".Length..]
                        : entry.FullName;

                    if (string.IsNullOrEmpty(rel) || rel.EndsWith('/')) continue;

                    var dest = Path.GetFullPath(Path.Combine(exeDir, rel));
                    if (!dest.StartsWith(exeDirSlash, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException($"Zip-slip detected: {entry.FullName}");

                    entries.Add((entry, dest));
                }

                bool renamed = false;
                try
                {
                    if (File.Exists(bakPath)) File.Delete(bakPath);
                    File.Move(currentExe, bakPath);
                    renamed = true;

                    // Wipe root-level files (skip preserved and *.bak)
                    foreach (var file in Directory.EnumerateFiles(exeDir))
                    {
                        var full = Path.GetFullPath(file);
                        if (full.EndsWith(".bak", StringComparison.OrdinalIgnoreCase)) continue;
                        if (IsPreserved(full, preserved)) continue;
                        File.Delete(full);
                    }

                    // Delete non-preserved subdirectories
                    foreach (var dir in Directory.EnumerateDirectories(exeDir))
                    {
                        var dirSlash = Path.GetFullPath(dir) + Path.DirectorySeparatorChar;
                        if (Array.Exists(preserved, p => p.StartsWith(dirSlash, StringComparison.OrdinalIgnoreCase))) continue;
                        try { Directory.Delete(dir, true); } catch { }
                    }

                    // Extract, skipping preserved paths
                    foreach (var (entry, dest) in entries)
                    {
                        if (IsPreserved(dest, preserved)) continue;
                        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                        entry.ExtractToFile(dest, overwrite: true);
                    }
                }
                catch
                {
                    if (renamed && File.Exists(bakPath) && !File.Exists(currentExe))
                        File.Move(bakPath, currentExe);
                    throw;
                }
            }

            Process.Start(new ProcessStartInfo(currentExe) { UseShellExecute = true });
            Environment.Exit(0);
        }
        finally
        {
            try { File.Delete(tempZip); } catch { }
        }
    }

    private static bool IsPreserved(string fullPath, string[] preserved) =>
        Array.Exists(preserved, p =>
            fullPath.StartsWith(p, StringComparison.OrdinalIgnoreCase) ||
            fullPath.Equals(p.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase));
}
