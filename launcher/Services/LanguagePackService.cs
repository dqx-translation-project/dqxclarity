using DqxClarity.Launcher.Models;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DqxClarity.Launcher.Services;

/// <summary>Per-pack HTTP cache validators, persisted to a sidecar so startup checks are cheap.</summary>
public record PackUpdateRecord
{
    [JsonPropertyName("etag")]         public string? Etag { get; init; }
    [JsonPropertyName("lastModified")] public string? LastModified { get; init; }
    [JsonPropertyName("checkedAt")]    public string? CheckedAt { get; init; }
}

/// <summary>Outcome of an update check. When <see cref="DownloadedBytes"/> is non-null the new pack
/// is already in hand (a check that had to fetch the whole body), so applying it avoids a re-download.</summary>
public sealed class UpdateCheckResult
{
    public bool    UpdateAvailable;
    public byte[]? DownloadedBytes;
    public string? RemoteSha;
    public string  Message = "";
}

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
        var dir = SourceLanguagePacksDir();
        return Directory
            .EnumerateFiles(dir, "*.zip", SearchOption.TopDirectoryOnly)
            .Concat(Directory.EnumerateFiles(dir, "*.clpk", SearchOption.TopDirectoryOnly))
            .OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
            .Select(ReadLanguagePack)
            .ToList();
    }

    private static LanguagePack ReadLanguagePack(string path)
    {
        try
        {
            var (payload, meta) = ClpkFormat.OpenPayload(path);
            using var _payload = payload;

            // Language packs are CLPK containers; their metadata lives in the header.
            if (meta == null)
                return InvalidLanguagePack(path, "Not a Clarity language pack (.clpk)");

            var normalizedMods = (meta.GameMods ?? [])
                .Select(NormalizeZipPath)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (normalizedMods.Count == 0)
                return InvalidLanguagePack(path, "Pack lists no game files to install");

            foreach (var item in normalizedMods)
                ValidateRelativeZipPath(item);

            return new LanguagePack
            {
                Name        = string.IsNullOrWhiteSpace(meta.Name) ? Path.GetFileNameWithoutExtension(path) : meta.Name,
                Author      = meta.Author ?? "",
                Language    = meta.Language ?? "",
                Created     = FormatBuiltAt(meta.BuiltAt),
                Path        = path,
                DownloadUrl = meta.DownloadUrl ?? "",
                GameMods    = normalizedMods,
                CanActivate = true,
                Status      = "Ready",
            };
        }
        catch (Exception ex)
        {
            return InvalidLanguagePack(path, ex.Message);
        }
    }

    private static LanguagePack InvalidLanguagePack(string path, string reason) =>
        new()
        {
            Name = Path.GetFileNameWithoutExtension(path),
            Path = path,
            CanActivate = false,
            Status = reason,
        };

    private static string FormatBuiltAt(long unixSeconds)
    {
        if (unixSeconds <= 0) return "";
        return DateTimeOffset.FromUnixTimeSeconds(unixSeconds).LocalDateTime.ToString("yyyy-MM-dd HH:mm");
    }

    /// <summary>Manual "Check Updates": runs the CLPK-aware check for each pack and flags HasUpdate.</summary>
    public async Task CheckUpdatesAsync(IEnumerable<LanguagePack> languagePacks)
    {
        foreach (var pack in languagePacks.Where(m => m.CanActivate))
        {
            if (string.IsNullOrWhiteSpace(pack.DownloadUrl))
            {
                pack.Status = "No update url";
                continue;
            }

            try
            {
                pack.Status = "Checking...";
                var check = await CheckForUpdateAsync(pack);
                pack.HasUpdate = check.UpdateAvailable;
                pack.Status = check.UpdateAvailable ? "Update available" : check.Message;
            }
            catch (Exception ex)
            {
                pack.HasUpdate = false;
                pack.Status = $"Update check failed: {ex.Message}";
            }
        }
    }

    public Task<LanguagePack> DownloadUpdateAsync(LanguagePack pack) =>
        ApplyUpdateAsync(pack, null);

    // ── CLPK-aware updater ────────────────────────────────────────────────
    //
    // Tiered check (validated against HTTP semantics):
    //   1. If we have a stored ETag/Last-Modified, send a conditional GET (If-None-Match /
    //      If-Modified-Since, Cache-Control: no-cache). 304 => unchanged. 200 => compare the
    //      body's sha to the local sha (the server may have ignored the conditional).
    //   2. Otherwise Range-peek bytes 0-2047 to read the remote CLPK header's sha256 without
    //      pulling the whole payload; compare to the local sha. (206 expected; a 200 means the
    //      server ignored Range and returned the full body, which we then compare directly.)
    // The sha — not the ETag — is the authority for "actually changed"; ETag/304 is only the
    // fast path for "definitely unchanged". Any ETag/Last-Modified seen is stored for next time.

    private string UpdateStatePath() => Path.Combine(SourceLanguagePacksDir(), ".update-state.json");

    private Dictionary<string, PackUpdateRecord> LoadUpdateState()
    {
        try
        {
            var path = UpdateStatePath();
            if (!File.Exists(path)) return new(StringComparer.OrdinalIgnoreCase);
            var parsed = JsonSerializer.Deserialize<Dictionary<string, PackUpdateRecord>>(File.ReadAllText(path));
            return parsed == null
                ? new(StringComparer.OrdinalIgnoreCase)
                : new(parsed, StringComparer.OrdinalIgnoreCase);
        }
        catch { return new(StringComparer.OrdinalIgnoreCase); }
    }

    private void SaveUpdateState(Dictionary<string, PackUpdateRecord> state)
    {
        try
        {
            EnsureSourceLanguagePacksFolder();
            File.WriteAllText(UpdateStatePath(),
                JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* sidecar is a cache; failing to persist only costs a redundant check next time */ }
    }

    private void RecordValidators(Dictionary<string, PackUpdateRecord> state, string fileName, HttpResponseMessage resp)
    {
        var etag = resp.Headers.ETag?.ToString();
        var lastMod = resp.Content.Headers.LastModified?.ToString("o");
        state[fileName] = new PackUpdateRecord
        {
            Etag         = string.IsNullOrEmpty(etag) ? null : etag,
            LastModified = lastMod,
            CheckedAt    = DateTimeOffset.UtcNow.ToString("o"),
        };
        SaveUpdateState(state);
    }

    private static string ComputeLocalPayloadSha(string path)
    {
        var (payload, _) = ClpkFormat.OpenPayload(path);
        using var _p = payload;
        return ClpkFormat.ComputeSha256Hex(payload);
    }

    private static string RemoteShaFromBytes(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes);
        if (ClpkFormat.TryReadHeader(ms, out var meta, out _, out _) && !string.IsNullOrEmpty(meta!.Sha256))
            return meta.Sha256.ToLowerInvariant();
        // Remote is a plain zip (no CLPK header): its bytes ARE the payload.
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static HttpClient NewHttp()
    {
        var http = new HttpClient();
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("dqxclarity-launcher", "1.0"));
        return http;
    }

    public async Task<UpdateCheckResult> CheckForUpdateAsync(LanguagePack pack)
    {
        var result = new UpdateCheckResult();
        if (string.IsNullOrWhiteSpace(pack.DownloadUrl)) { result.Message = "No update url"; return result; }

        var fileName = Path.GetFileName(pack.Path);
        var state = LoadUpdateState();
        state.TryGetValue(fileName, out var rec);

        string localSha;
        try { localSha = ComputeLocalPayloadSha(pack.Path); } catch { localSha = ""; }

        using var http = NewHttp();
        var haveValidators = rec != null && (!string.IsNullOrEmpty(rec.Etag) || !string.IsNullOrEmpty(rec.LastModified));

        if (haveValidators)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, pack.DownloadUrl);
            req.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
            if (!string.IsNullOrEmpty(rec!.Etag))
                try { req.Headers.IfNoneMatch.Add(EntityTagHeaderValue.Parse(rec.Etag)); } catch { }
            if (!string.IsNullOrEmpty(rec.LastModified) && DateTimeOffset.TryParse(rec.LastModified, out var lm))
                req.Headers.IfModifiedSince = lm;

            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);
            if (resp.StatusCode == HttpStatusCode.NotModified)
            {
                RecordValidators(state, fileName, resp);
                result.Message = "Up to date";
                return result;
            }
            if (resp.IsSuccessStatusCode)
            {
                var bytes = await resp.Content.ReadAsByteArrayAsync();
                RecordValidators(state, fileName, resp);
                var remoteSha = RemoteShaFromBytes(bytes);
                if (!string.IsNullOrEmpty(remoteSha) && !remoteSha.Equals(localSha, StringComparison.OrdinalIgnoreCase))
                {
                    result.UpdateAvailable = true;
                    result.DownloadedBytes = bytes;
                    result.RemoteSha = remoteSha;
                    result.Message = "Update available";
                }
                else result.Message = "Up to date";
                return result;
            }
            result.Message = $"Update check failed: HTTP {(int)resp.StatusCode}";
            return result;
        }

        // No validators yet — Range-peek the CLPK header.
        using (var req = new HttpRequestMessage(HttpMethod.Get, pack.DownloadUrl))
        {
            req.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
            req.Headers.Range = new RangeHeaderValue(0, 2047);
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);

            if (resp.StatusCode == HttpStatusCode.PartialContent)
            {
                var headBytes = await resp.Content.ReadAsByteArrayAsync();
                RecordValidators(state, fileName, resp);
                string remoteSha = "";
                using (var ms = new MemoryStream(headBytes))
                    if (ClpkFormat.TryReadHeader(ms, out var meta, out _, out _) && !string.IsNullOrEmpty(meta!.Sha256))
                        remoteSha = meta.Sha256.ToLowerInvariant();

                if (string.IsNullOrEmpty(remoteSha))
                {
                    // Remote isn't a CLPK (or header exceeds the peek window): fall back to a full compare.
                    var full = await http.GetByteArrayAsync(pack.DownloadUrl);
                    remoteSha = RemoteShaFromBytes(full);
                    if (!string.IsNullOrEmpty(remoteSha) && !remoteSha.Equals(localSha, StringComparison.OrdinalIgnoreCase))
                    {
                        result.UpdateAvailable = true;
                        result.DownloadedBytes = full;
                    }
                }
                else
                {
                    result.UpdateAvailable = !remoteSha.Equals(localSha, StringComparison.OrdinalIgnoreCase);
                }
                result.RemoteSha = remoteSha;
                result.Message = result.UpdateAvailable ? "Update available" : "Up to date";
                return result;
            }

            if (resp.IsSuccessStatusCode) // server ignored Range; full body returned
            {
                var bytes = await resp.Content.ReadAsByteArrayAsync();
                RecordValidators(state, fileName, resp);
                var remoteSha = RemoteShaFromBytes(bytes);
                if (!string.IsNullOrEmpty(remoteSha) && !remoteSha.Equals(localSha, StringComparison.OrdinalIgnoreCase))
                {
                    result.UpdateAvailable = true;
                    result.DownloadedBytes = bytes;
                    result.RemoteSha = remoteSha;
                    result.Message = "Update available";
                }
                else result.Message = "Up to date";
                return result;
            }

            result.Message = $"Update check failed: HTTP {(int)resp.StatusCode}";
            return result;
        }
    }

    /// <summary>Downloads (unless bytes are already in hand), verifies sha256 for CLPK packs, and
    /// replaces the local pack file. Returns the re-read pack.</summary>
    public async Task<LanguagePack> ApplyUpdateAsync(LanguagePack pack, byte[]? alreadyDownloaded)
    {
        if (string.IsNullOrWhiteSpace(pack.DownloadUrl))
            throw new InvalidDataException("No download URL");

        byte[] bytes;
        if (alreadyDownloaded != null)
        {
            bytes = alreadyDownloaded;
        }
        else
        {
            using var http = NewHttp();
            bytes = await http.GetByteArrayAsync(pack.DownloadUrl);
        }

        // Integrity: if the download is a CLPK, its payload sha must match the header.
        using (var ms = new MemoryStream(bytes))
            if (ClpkFormat.TryReadHeader(ms, out var meta, out var off, out var len) && !string.IsNullOrEmpty(meta!.Sha256))
            {
                using var payload = new SubStream(ms, off, len, leaveOpen: true);
                var actual = ClpkFormat.ComputeSha256Hex(payload);
                if (!actual.Equals(meta.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Downloaded pack failed sha256 verification.");
            }

        var temp = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(temp, bytes);
            var probe = ReadLanguagePack(temp);
            if (!probe.CanActivate)
                throw new InvalidDataException(probe.Status);

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

        // Preserve the chosen file's extension (.clpk stays .clpk), defaulting to .clpk.
        var ext = Path.GetExtension(sourceZipPath);
        if (string.IsNullOrWhiteSpace(ext)) ext = ".clpk";
        var baseName = Path.GetFileNameWithoutExtension(sourceZipPath).Trim();
        foreach (var c in Path.GetInvalidFileNameChars())
            baseName = baseName.Replace(c, '_');
        if (string.IsNullOrWhiteSpace(baseName)) baseName = "language-pack";
        var destPath = Path.Combine(SourceLanguagePacksDir(), baseName + ext);

        // If the chosen file already lives in the language-packs folder, don't copy onto itself.
        if (!string.Equals(Path.GetFullPath(sourceZipPath), Path.GetFullPath(destPath), StringComparison.OrdinalIgnoreCase))
            File.Copy(sourceZipPath, destPath, overwrite: true);

        return ReadLanguagePack(destPath);
    }

    /// <summary>
    /// Builds a CLPK container from a plain input .zip: validates the input is a zip, hashes it, and
    /// stamps a CLPK header (sha256 + metadata) in front of the payload. Overwrites the output if it
    /// already exists. File IO and hashing run on a background thread.
    /// </summary>
    public async Task BuildClpkAsync(string inputZipPath, string outputClpkPath,
        string name, string author, string language, string downloadUrl)
    {
        if (string.IsNullOrWhiteSpace(inputZipPath) || !File.Exists(inputZipPath))
            throw new FileNotFoundException($"Input zip file not found: {inputZipPath}");
        if (string.IsNullOrWhiteSpace(outputClpkPath))
            throw new InvalidDataException("No output path specified.");

        await Task.Run(() =>
        {
            var zipBytes = File.ReadAllBytes(inputZipPath);
            if (zipBytes.Length < 2 || zipBytes[0] != (byte)'P' || zipBytes[1] != (byte)'K')
                throw new InvalidDataException("Input file is not a valid .zip archive (missing 'PK' signature).");

            // game_mods is derived from the zip's top-level entries (each top-level folder/file except mod.jsons).
            var gameMods = new List<string>();
            using (var ms = new MemoryStream(zipBytes))
            using (var archive = new ZipArchive(ms, ZipArchiveMode.Read))
            {
                foreach (var entry in archive.Entries)
                {
                    var norm = NormalizeZipPath(entry.FullName);
                    if (string.IsNullOrWhiteSpace(norm) || norm.Equals("mod.jsons", StringComparison.OrdinalIgnoreCase))
                        continue;
                    var top = norm.Split('/')[0];
                    if (!string.IsNullOrWhiteSpace(top) && !gameMods.Contains(top, StringComparer.OrdinalIgnoreCase))
                        gameMods.Add(top);
                }
            }
            if (gameMods.Count == 0)
                throw new InvalidDataException("Input zip has no installable files (it is empty or contains only mod.jsons).");

            var meta = new ClpkMetadata
            {
                Name        = string.IsNullOrWhiteSpace(name) ? Path.GetFileNameWithoutExtension(inputZipPath) : name,
                Author      = author ?? "",
                Language    = language ?? "",
                BuiltAt     = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                DownloadUrl = downloadUrl ?? "",
                GameMods    = gameMods,
            };

            using var output = new FileStream(outputClpkPath, FileMode.Create, FileAccess.Write, FileShare.None);
            ClpkFormat.Write(output, zipBytes, meta);
        });
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

        var (payload, _) = ClpkFormat.OpenPayload(pack.Path);
        using var _payload = payload;
        using var archive = new ZipArchive(payload, ZipArchiveMode.Read);
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
            throw new InvalidDataException("No files in the pack matched its game_mods entries.");

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

            var (payload, _) = ClpkFormat.OpenPayload(pack.Path);
            using var _payload = payload;
            using var archive = new ZipArchive(payload, ZipArchiveMode.Read);
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

    private static string NormalizeZipPath(string path) =>
        path.Replace('\\', '/').Trim('/');

    private static void ValidateRelativeZipPath(string path)
    {
        if (Path.IsPathRooted(path) || path.Split('/').Any(p => p == ".."))
            throw new InvalidDataException($"Unsafe path in pack metadata: {path}");
    }
}
