using DqxClarity.Launcher.Models;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text.Json;

namespace DqxClarity.Launcher.Services;

public class LanguagePackService
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

    // "mods" is the folder name the dragonhook proxy DLL scans in the game dir; do not rename.
    private static string GameModsDir(string installDir) =>
        Path.Combine(GameDir(installDir), "mods");

    private static string SourceLanguagePacksDir() =>
        Path.Combine(AppDir(), "language-packs");

    private static string TargetDll(string installDir) =>
        Path.Combine(GameDir(installDir), "version.dll");

    public void EnsureSourceLanguagePacksFolder() =>
        Directory.CreateDirectory(SourceLanguagePacksDir());

    public string GetSourceLanguagePacksFolder()
    {
        EnsureSourceLanguagePacksFolder();
        return SourceLanguagePacksDir();
    }

    public void EnsureGameModsFolder(string installDir)
    {
        if (string.IsNullOrWhiteSpace(installDir)) return;
        Directory.CreateDirectory(GameModsDir(installDir));
    }

    public void EnsureFolders(string installDir)
    {
        EnsureSourceLanguagePacksFolder();
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
        EnsureSourceLanguagePacksFolder();
        EnsureGameModsFolder(installDir);

        using var stream = typeof(LanguagePackService).Assembly.GetManifestResourceStream("version.dll")
            ?? throw new FileNotFoundException("The embedded language pack support DLL is missing.");
        using var target = File.Create(TargetDll(installDir));
        stream.CopyTo(target);
    }

    public void DisableSupport(string installDir)
    {
        var target = TargetDll(installDir);
        if (File.Exists(target))
            File.Delete(target);
    }

    public List<LanguagePack> ScanLanguagePacks()
    {
        EnsureSourceLanguagePacksFolder();
        return Directory
            .EnumerateFiles(SourceLanguagePacksDir(), "*.zip", SearchOption.TopDirectoryOnly)
            .OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
            .Select(ReadLanguagePack)
            .ToList();
    }

    private static LanguagePack ReadLanguagePack(string path)
    {
        try
        {
            using var archive = ZipFile.OpenRead(path);
            var manifestEntry = archive.Entries.FirstOrDefault(e =>
                NormalizeZipPath(e.FullName).Equals("mod.jsons", StringComparison.OrdinalIgnoreCase));
            if (manifestEntry == null)
                return InvalidLanguagePack(path, "Missing mod.jsons");

            using var stream = manifestEntry.Open();
            var manifest = JsonSerializer.Deserialize<LanguagePackManifest>(stream, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            }) ?? throw new InvalidDataException("mod.jsons is empty");

            var gameMods = manifest.GameMods
                .Select(NormalizeZipPath)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (gameMods.Count == 0)
                return InvalidLanguagePack(path, "mod.jsons has no game_mods entries", manifest);

            foreach (var item in gameMods)
                ValidateRelativeZipPath(item);

            return new LanguagePack
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
            return InvalidLanguagePack(path, ex.Message);
        }
    }

    private static LanguagePack InvalidLanguagePack(string path, string reason, LanguagePackManifest? manifest = null) =>
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

    public async Task CheckUpdatesAsync(IEnumerable<LanguagePack> languagePacks)
    {
        using var http = new HttpClient();
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("dqxclarity-launcher", "1.0"));

        foreach (var pack in languagePacks.Where(m => m.CanActivate))
        {
            if (string.IsNullOrWhiteSpace(pack.DownloadUrl))
            {
                pack.Status = "No download_url";
                continue;
            }

            try
            {
                pack.Status = "Checking...";
                var remote = await ReadRemoteManifest(http, pack.DownloadUrl);
                pack.RemoteVersion = remote.Version;

                var compare = CompareVersions(remote.Version, pack.Version);
                pack.HasUpdate = compare > 0;
                pack.Status = compare > 0
                    ? $"Update available: {remote.Version}"
                    : compare == 0
                        ? "Up to date"
                        : $"Local newer: {pack.Version}";
            }
            catch (Exception ex)
            {
                pack.HasUpdate = false;
                pack.Status = $"Update check failed: {ex.Message}";
            }
        }
    }

    public async Task<LanguagePack> DownloadUpdateAsync(LanguagePack pack)
    {
        if (string.IsNullOrWhiteSpace(pack.DownloadUrl))
            throw new InvalidDataException("No download_url");

        using var http = new HttpClient();
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("dqxclarity-launcher", "1.0"));

        var temp = Path.GetTempFileName();
        try
        {
            var bytes = await http.GetByteArrayAsync(pack.DownloadUrl);
            await File.WriteAllBytesAsync(temp, bytes);

            var downloaded = ReadLanguagePack(temp);
            if (!downloaded.CanActivate)
                throw new InvalidDataException(downloaded.Status);

            File.Copy(temp, pack.Path, overwrite: true);
            return ReadLanguagePack(pack.Path);
        }
        finally
        {
            try { File.Delete(temp); } catch { }
        }
    }

    public async Task<LanguagePack> DownloadCatalogPackAsync(LanguagePackCatalogEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.DownloadUrl))
            throw new InvalidDataException("Catalog entry has no download URL.");

        EnsureSourceLanguagePacksFolder();

        using var http = new HttpClient();
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("dqxclarity-launcher", "1.0"));

        var fileName = SanitizeZipFileName(entry.Name);
        var destPath = Path.Combine(SourceLanguagePacksDir(), fileName);

        var temp = Path.GetTempFileName();
        try
        {
            var bytes = await http.GetByteArrayAsync(entry.DownloadUrl);
            await File.WriteAllBytesAsync(temp, bytes);

            var downloaded = ReadLanguagePack(temp);
            if (!downloaded.CanActivate)
                throw new InvalidDataException(downloaded.Status);

            File.Copy(temp, destPath, overwrite: true);
            return ReadLanguagePack(destPath);
        }
        finally
        {
            try { File.Delete(temp); } catch { }
        }
    }

    public LanguagePack ImportZipFromDisk(string sourceZipPath)
    {
        if (string.IsNullOrWhiteSpace(sourceZipPath) || !File.Exists(sourceZipPath))
            throw new FileNotFoundException($"Zip file not found: {sourceZipPath}");

        EnsureSourceLanguagePacksFolder();

        // Validate before importing so we don't copy a broken archive.
        var probe = ReadLanguagePack(sourceZipPath);
        if (!probe.CanActivate)
            throw new InvalidDataException(probe.Status);

        var fileName = SanitizeZipFileName(Path.GetFileNameWithoutExtension(sourceZipPath));
        var destPath = Path.Combine(SourceLanguagePacksDir(), fileName);

        // If the chosen file already lives in the language-packs folder, don't copy onto itself.
        if (!string.Equals(Path.GetFullPath(sourceZipPath), Path.GetFullPath(destPath), StringComparison.OrdinalIgnoreCase))
            File.Copy(sourceZipPath, destPath, overwrite: true);

        return ReadLanguagePack(destPath);
    }

    private static string SanitizeZipFileName(string name)
    {
        var safe = name.Trim();
        foreach (var c in Path.GetInvalidFileNameChars())
            safe = safe.Replace(c, '_');
        if (string.IsNullOrWhiteSpace(safe))
            safe = "language-pack";
        if (!safe.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            safe += ".zip";
        return safe;
    }

    private static async Task<LanguagePackManifest> ReadRemoteManifest(HttpClient http, string url)
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
            return JsonSerializer.Deserialize<LanguagePackManifest>(stream, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            }) ?? throw new InvalidDataException("Remote mod.jsons is empty");
        }
        catch (InvalidDataException)
        {
            using var ms = new MemoryStream(bytes);
            return await JsonSerializer.DeserializeAsync<LanguagePackManifest>(ms, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            }) ?? throw new InvalidDataException("Remote manifest is empty");
        }
    }

    public int ExtractLanguagePack(string installDir, LanguagePack pack)
    {
        EnsureSourceLanguagePacksFolder();
        EnsureGameModsFolder(installDir);
        if (!File.Exists(pack.Path))
            throw new FileNotFoundException($"Language pack archive not found: {pack.Path}");

        var modsDir = Path.GetFullPath(GameModsDir(installDir));
        var root = modsDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                   + Path.DirectorySeparatorChar;
        var extracted = 0;

        if (!pack.CanActivate)
            throw new InvalidDataException(pack.Status);

        using var archive = ZipFile.OpenRead(pack.Path);
        foreach (var entry in archive.Entries)
        {
            var normalizedEntry = NormalizeZipPath(entry.FullName);
            if (string.IsNullOrWhiteSpace(normalizedEntry) || normalizedEntry.Equals("mod.jsons", StringComparison.OrdinalIgnoreCase))
                continue;

            if (!pack.GameMods.Any(source => IsUnderSource(normalizedEntry, source)))
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

    public int RebuildGameModsFolder(string installDir, IEnumerable<LanguagePack> activeLanguagePacks)
    {
        EnsureGameModsFolder(installDir);

        var packs = activeLanguagePacks.ToList();
        ValidateNoOutputConflicts(packs);

        var modsDir = GameModsDir(installDir);
        foreach (var file in Directory.EnumerateFiles(modsDir))
            File.Delete(file);
        foreach (var dir in Directory.EnumerateDirectories(modsDir))
            Directory.Delete(dir, recursive: true);

        var total = 0;
        foreach (var pack in packs)
            total += ExtractLanguagePack(installDir, pack);
        return total;
    }

    private static void ValidateNoOutputConflicts(IReadOnlyList<LanguagePack> activeLanguagePacks)
    {
        var outputs = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var pack in activeLanguagePacks)
        {
            if (!pack.CanActivate)
                throw new InvalidDataException(pack.Status);
            if (!File.Exists(pack.Path))
                throw new FileNotFoundException($"Language pack archive not found: {pack.Path}");

            using var archive = ZipFile.OpenRead(pack.Path);
            foreach (var entry in archive.Entries)
            {
                if (string.IsNullOrEmpty(entry.Name))
                    continue;

                var normalizedEntry = NormalizeZipPath(entry.FullName);
                if (string.IsNullOrWhiteSpace(normalizedEntry)
                    || normalizedEntry.Equals("mod.jsons", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!pack.GameMods.Any(source => IsUnderSource(normalizedEntry, source)))
                    continue;

                ValidateRelativeZipPath(normalizedEntry);

                if (!outputs.TryGetValue(normalizedEntry, out var owners))
                {
                    owners = [];
                    outputs[normalizedEntry] = owners;
                }

                if (!owners.Contains(pack.Name, StringComparer.OrdinalIgnoreCase))
                    owners.Add(pack.Name);
            }
        }

        var conflicts = outputs
            .Where(kv => kv.Value.Count > 1)
            .Take(10)
            .Select(kv => $"{kv.Key}: {string.Join(", ", kv.Value)}")
            .ToList();

        if (conflicts.Count > 0)
            throw new InvalidDataException(
                "Language pack file conflict detected. These files are provided by multiple active language packs:\n"
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
