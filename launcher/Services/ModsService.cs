using DqxClarity.Launcher.Models;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text.Json;

namespace DqxClarity.Launcher.Services;

public class ModsService
{
    private static string AppDir()
    {
        var exeDir = Path.GetDirectoryName(Environment.ProcessPath ?? "") ?? AppContext.BaseDirectory;
        var dir = exeDir;
        for (var i = 0; i < 4; i++)
        {
            if (File.Exists(Path.Combine(dir, "main.py")))
                return Path.GetFullPath(dir);
            dir = Path.GetFullPath(Path.Combine(dir, ".."));
        }
        return Path.GetFullPath(exeDir);
    }

    private static string GameDir(string installDir) =>
        Path.Combine(installDir, "Game");

    private static string GameModsDir(string installDir) =>
        Path.Combine(GameDir(installDir), "mods");

    private static string SourceModsDir() =>
        Path.Combine(AppDir(), "mods");

    private static string TargetDll(string installDir) =>
        Path.Combine(GameDir(installDir), "version.dll");

    public void EnsureSourceModsFolder() =>
        Directory.CreateDirectory(SourceModsDir());

    public string GetSourceModsFolder()
    {
        EnsureSourceModsFolder();
        return SourceModsDir();
    }

    public void EnsureGameModsFolder(string installDir)
    {
        if (string.IsNullOrWhiteSpace(installDir)) return;
        Directory.CreateDirectory(GameModsDir(installDir));
    }

    public void EnsureFolders(string installDir)
    {
        EnsureSourceModsFolder();
        EnsureGameModsFolder(installDir);
    }

    public void PrepareRuntime(string installDir, bool enabled)
    {
        EnsureFolders(installDir);
        if (enabled)
            EnableSupport(installDir);
        else
            DisableSupport(installDir);
    }

    public void CleanupRuntime(string installDir) => DisableSupport(installDir);

    public void EnableSupport(string installDir)
    {
        EnsureSourceModsFolder();
        EnsureGameModsFolder(installDir);

        using var stream = typeof(ModsService).Assembly.GetManifestResourceStream("version.dll")
            ?? throw new FileNotFoundException("The embedded mod support DLL is missing.");
        using var target = File.Create(TargetDll(installDir));
        stream.CopyTo(target);
    }

    public void DisableSupport(string installDir)
    {
        var target = TargetDll(installDir);
        if (File.Exists(target))
            File.Delete(target);
    }

    public List<ModFile> ScanZipMods()
    {
        EnsureSourceModsFolder();
        return Directory
            .EnumerateFiles(SourceModsDir(), "*.zip", SearchOption.TopDirectoryOnly)
            .OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
            .Select(ReadModFile)
            .ToList();
    }

    private static ModFile ReadModFile(string path)
    {
        try
        {
            using var archive = ZipFile.OpenRead(path);
            var manifestEntry = archive.Entries.FirstOrDefault(e =>
                NormalizeZipPath(e.FullName).Equals("mod.jsons", StringComparison.OrdinalIgnoreCase));
            if (manifestEntry == null)
                return InvalidMod(path, "Missing mod.jsons");

            using var stream = manifestEntry.Open();
            var manifest = JsonSerializer.Deserialize<ModManifest>(stream, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            }) ?? throw new InvalidDataException("mod.jsons is empty");

            var gameMods = manifest.GameMods
                .Select(NormalizeZipPath)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (gameMods.Count == 0)
                return InvalidMod(path, "mod.jsons has no game_mods entries", manifest);

            foreach (var item in gameMods)
                ValidateRelativeZipPath(item);

            return new ModFile
            {
                Type = string.IsNullOrWhiteSpace(manifest.Type) ? "Unknown" : manifest.Type,
                Name = string.IsNullOrWhiteSpace(manifest.Name) ? Path.GetFileNameWithoutExtension(path) : manifest.Name,
                Version = manifest.Version,
                Author = manifest.Author,
                Description = manifest.Description,
                Path = path,
                DownloadUrl = FirstNonEmpty(manifest.DownloadUrl, manifest.UpdateUrl, manifest.Homepage),
                GameMods = gameMods,
                CanActivate = true,
                Status = "Ready",
            };
        }
        catch (Exception ex)
        {
            return InvalidMod(path, ex.Message);
        }
    }

    private static ModFile InvalidMod(string path, string reason, ModManifest? manifest = null) =>
        new()
        {
            Type = string.IsNullOrWhiteSpace(manifest?.Type) ? "Invalid" : manifest!.Type,
            Name = string.IsNullOrWhiteSpace(manifest?.Name) ? Path.GetFileNameWithoutExtension(path) : manifest!.Name,
            Version = manifest?.Version ?? "",
            Author = manifest?.Author ?? "",
            Path = path,
            DownloadUrl = manifest == null ? "" : FirstNonEmpty(manifest.DownloadUrl, manifest.UpdateUrl, manifest.Homepage),
            CanActivate = false,
            Status = reason,
        };

    public async Task CheckUpdatesAsync(IEnumerable<ModFile> mods)
    {
        using var http = new HttpClient();
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("dqxclarity-launcher", "1.0"));

        foreach (var mod in mods.Where(m => m.CanActivate))
        {
            if (string.IsNullOrWhiteSpace(mod.DownloadUrl))
            {
                mod.Status = "No download_url";
                continue;
            }

            try
            {
                mod.Status = "Checking...";
                var remote = await ReadRemoteManifest(http, mod.DownloadUrl);
                mod.RemoteVersion = remote.Version;

                var compare = CompareVersions(remote.Version, mod.Version);
                mod.HasUpdate = compare > 0;
                mod.Status = compare > 0
                    ? $"Update available: {remote.Version}"
                    : compare == 0
                        ? "Up to date"
                        : $"Local newer: {mod.Version}";
            }
            catch (Exception ex)
            {
                mod.HasUpdate = false;
                mod.Status = $"Update check failed: {ex.Message}";
            }
        }
    }

    public async Task<ModFile> DownloadUpdateAsync(ModFile mod)
    {
        if (string.IsNullOrWhiteSpace(mod.DownloadUrl))
            throw new InvalidDataException("No download_url");

        using var http = new HttpClient();
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("dqxclarity-launcher", "1.0"));

        var temp = Path.GetTempFileName();
        try
        {
            var bytes = await http.GetByteArrayAsync(mod.DownloadUrl);
            await File.WriteAllBytesAsync(temp, bytes);

            var downloaded = ReadModFile(temp);
            if (!downloaded.CanActivate)
                throw new InvalidDataException(downloaded.Status);

            File.Copy(temp, mod.Path, overwrite: true);
            return ReadModFile(mod.Path);
        }
        finally
        {
            try { File.Delete(temp); } catch { }
        }
    }

    private static async Task<ModManifest> ReadRemoteManifest(HttpClient http, string url)
    {
        var bytes = await http.GetByteArrayAsync(url);

        try
        {
            using var ms = new MemoryStream(bytes);
            using var archive = new ZipArchive(ms, ZipArchiveMode.Read);
            var manifestEntry = archive.Entries.FirstOrDefault(e =>
                NormalizeZipPath(e.FullName).Equals("mod.jsons", StringComparison.OrdinalIgnoreCase));
            if (manifestEntry == null)
                throw new InvalidDataException("Remote zip has no mod.jsons");
            using var stream = manifestEntry.Open();
            return JsonSerializer.Deserialize<ModManifest>(stream, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            }) ?? throw new InvalidDataException("Remote mod.jsons is empty");
        }
        catch (InvalidDataException)
        {
            using var ms = new MemoryStream(bytes);
            return await JsonSerializer.DeserializeAsync<ModManifest>(ms, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            }) ?? throw new InvalidDataException("Remote manifest is empty");
        }
    }

    public int ExtractZipMod(string installDir, ModFile mod)
    {
        EnsureSourceModsFolder();
        EnsureGameModsFolder(installDir);
        if (!File.Exists(mod.Path))
            throw new FileNotFoundException($"Mod archive not found: {mod.Path}");

        var modsDir = Path.GetFullPath(GameModsDir(installDir));
        var root = modsDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                   + Path.DirectorySeparatorChar;
        var extracted = 0;

        if (!mod.CanActivate)
            throw new InvalidDataException(mod.Status);

        using var archive = ZipFile.OpenRead(mod.Path);
        foreach (var entry in archive.Entries)
        {
            var normalizedEntry = NormalizeZipPath(entry.FullName);
            if (string.IsNullOrWhiteSpace(normalizedEntry) || normalizedEntry.Equals("mod.jsons", StringComparison.OrdinalIgnoreCase))
                continue;

            if (!mod.GameMods.Any(source => IsUnderSource(normalizedEntry, source)))
                continue;

            var target = Path.GetFullPath(Path.Combine(modsDir, normalizedEntry));
            if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Unsafe path in archive: {normalizedEntry}");

            if (string.IsNullOrEmpty(entry.Name))
            {
                Directory.CreateDirectory(target);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            entry.ExtractToFile(target, overwrite: true);
            extracted++;
        }

        if (extracted == 0)
            throw new InvalidDataException("No files matched the game_mods entries in mod.jsons.");

        return extracted;
    }

    public int RebuildGameModsFolder(string installDir, IEnumerable<ModFile> activeMods)
    {
        EnsureGameModsFolder(installDir);

        var mods = activeMods.ToList();
        ValidateNoOutputConflicts(mods);

        var modsDir = GameModsDir(installDir);
        foreach (var file in Directory.EnumerateFiles(modsDir))
            File.Delete(file);
        foreach (var dir in Directory.EnumerateDirectories(modsDir))
            Directory.Delete(dir, recursive: true);

        var total = 0;
        foreach (var mod in mods)
            total += ExtractZipMod(installDir, mod);
        return total;
    }

    private static void ValidateNoOutputConflicts(IReadOnlyList<ModFile> activeMods)
    {
        var outputs = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var mod in activeMods)
        {
            if (!mod.CanActivate)
                throw new InvalidDataException(mod.Status);
            if (!File.Exists(mod.Path))
                throw new FileNotFoundException($"Mod archive not found: {mod.Path}");

            using var archive = ZipFile.OpenRead(mod.Path);
            foreach (var entry in archive.Entries)
            {
                if (string.IsNullOrEmpty(entry.Name))
                    continue;

                var normalizedEntry = NormalizeZipPath(entry.FullName);
                if (string.IsNullOrWhiteSpace(normalizedEntry)
                    || normalizedEntry.Equals("mod.jsons", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!mod.GameMods.Any(source => IsUnderSource(normalizedEntry, source)))
                    continue;

                ValidateRelativeZipPath(normalizedEntry);

                if (!outputs.TryGetValue(normalizedEntry, out var owners))
                {
                    owners = [];
                    outputs[normalizedEntry] = owners;
                }

                if (!owners.Contains(mod.Name, StringComparer.OrdinalIgnoreCase))
                    owners.Add(mod.Name);
            }
        }

        var conflicts = outputs
            .Where(kv => kv.Value.Count > 1)
            .Take(10)
            .Select(kv => $"{kv.Key}: {string.Join(", ", kv.Value)}")
            .ToList();

        if (conflicts.Count > 0)
            throw new InvalidDataException(
                "Mod file conflict detected. These files are provided by multiple active mods:\n"
                + string.Join("\n", conflicts));
    }

    private static bool IsUnderSource(string entry, string source) =>
        entry.Equals(source, StringComparison.OrdinalIgnoreCase)
        || entry.StartsWith(source.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase);

    private static string FirstNonEmpty(params string[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "";

    private static int CompareVersions(string remote, string local)
    {
        var r = ParseVersionParts(remote);
        var l = ParseVersionParts(local);
        var count = Math.Max(r.Count, l.Count);
        for (var i = 0; i < count; i++)
        {
            var rv = i < r.Count ? r[i] : 0;
            var lv = i < l.Count ? l[i] : 0;
            if (rv != lv) return rv.CompareTo(lv);
        }
        return string.Equals(remote, local, StringComparison.OrdinalIgnoreCase)
            ? 0
            : string.Compare(remote, local, StringComparison.OrdinalIgnoreCase);
    }

    private static List<int> ParseVersionParts(string version) =>
        version.Trim()
            .TrimStart('v', 'V')
            .Split(['.', '-', '_', '+'], StringSplitOptions.RemoveEmptyEntries)
            .TakeWhile(part => int.TryParse(part, out _))
            .Select(int.Parse)
            .ToList();

    private static string NormalizeZipPath(string path) =>
        path.Replace('\\', '/').Trim('/');

    private static void ValidateRelativeZipPath(string path)
    {
        if (Path.IsPathRooted(path) || path.Split('/').Any(p => p == ".."))
            throw new InvalidDataException($"Unsafe path in mod.jsons: {path}");
    }
}
