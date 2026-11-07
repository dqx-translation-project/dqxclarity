using DqxClarity.Models;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DqxClarity.Services;

/// <summary>Per-pack HTTP cache validators, persisted to a sidecar so startup checks are cheap.</summary>
public record PackUpdateRecord
{
    [JsonPropertyName("etag")]         public string? Etag { get; init; }
    [JsonPropertyName("lastModified")] public string? LastModified { get; init; }
    [JsonPropertyName("checkedAt")]    public string? CheckedAt { get; init; }

    // Payload sha of the LOCAL pack these validators were recorded against. The
    // ETag/Last-Modified only mean "unchanged" relative to the file on disk at
    // that moment, so they are trusted only while the local pack still has this
    // sha. Records without it (written before this field existed) are ignored.
    [JsonPropertyName("localSha")]     public string? LocalSha { get; init; }
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
    // Unlike ConfigService.AppDir() (a simple ExeDir() passthrough — this branch has no Python
    // sidecar to search for), this mirrors that same "just the exe's own folder" convention rather
    // than porting main branch's main.py-marker walk-up, which doesn't apply here.
    private static string AppDir() =>
        Path.GetDirectoryName(Environment.ProcessPath ?? "") ?? AppContext.BaseDirectory;

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

    /// <summary>True when version.dll (the language pack loader) is present in the game folder.</summary>
    public bool IsSupportInstalled(string installDir) =>
        !string.IsNullOrWhiteSpace(installDir) && File.Exists(TargetDll(installDir));

    /// <summary>Copies the embedded version.dll into the game folder so active packs load in-game.</summary>
    public void EnableSupport(string installDir)
    {
        EnsureSourceLanguagePacksFolder();
        EnsureGameModsFolder(installDir);

        using var stream = typeof(LanguagePackService).Assembly.GetManifestResourceStream("version.dll")
            ?? throw new FileNotFoundException("The embedded language pack support DLL is missing.");
        using var target = File.Create(TargetDll(installDir));
        stream.CopyTo(target);
    }

    /// <summary>Result of <see cref="RefreshSupportDllIfStale"/>.</summary>
    public enum SupportRefreshResult
    {
        /// <summary>version.dll isn't in the game folder (user hasn't installed it, or removed it) -- left alone.</summary>
        NotInstalled,
        /// <summary>The installed version.dll already matches the embedded one.</summary>
        UpToDate,
        /// <summary>The installed version.dll was out of date and has been replaced.</summary>
        Updated,
        /// <summary>It's out of date but couldn't be replaced (usually DQX is running and has it loaded). Retried next launch.</summary>
        Locked,
    }

    /// <summary>
    /// If version.dll is already in the game folder and differs from the copy embedded in this build,
    /// replaces it with the embedded one. Never installs it when it isn't there. The new file is written
    /// next to the target and moved into place, so a failure (e.g. the game has the DLL loaded) leaves the
    /// existing file untouched. Never throws for ordinary I/O problems.
    /// </summary>
    public SupportRefreshResult RefreshSupportDllIfStale(string installDir)
    {
        if (string.IsNullOrWhiteSpace(installDir)) return SupportRefreshResult.NotInstalled;

        var target = TargetDll(installDir);
        if (!File.Exists(target)) return SupportRefreshResult.NotInstalled;

        var temp = target + ".new";
        try
        {
            using var embedded = typeof(LanguagePackService).Assembly.GetManifestResourceStream("version.dll");
            if (embedded == null) return SupportRefreshResult.UpToDate; // nothing to compare against

            byte[] embeddedHash = SHA256.HashData(embedded);

            // ReadWrite|Delete sharing so hashing still works while the game has the DLL mapped.
            byte[] installedHash;
            using (var installed = new FileStream(target, FileMode.Open, FileAccess.Read,
                       FileShare.ReadWrite | FileShare.Delete))
                installedHash = SHA256.HashData(installed);

            if (embeddedHash.AsSpan().SequenceEqual(installedHash))
                return SupportRefreshResult.UpToDate;

            embedded.Position = 0;
            using (var output = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
                embedded.CopyTo(output);

            File.Move(temp, target, overwrite: true);
            return SupportRefreshResult.Updated;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
            return SupportRefreshResult.Locked;
        }
    }

    /// <summary>Removes version.dll from the game folder.</summary>
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

            // The whole zip payload is installed into Game\mods, so any valid CLPK is activatable.
            // Update URL: the pack's own (rarely set), else the catalog's URL for this language.
            var downloadUrl = !string.IsNullOrWhiteSpace(meta.DownloadUrl)
                ? meta.DownloadUrl
                : LanguagePackCatalog.DownloadUrlFor(meta.Language);

            return new LanguagePack
            {
                Author      = meta.Author ?? "",
                Language    = meta.Language ?? "",
                Updated     = FormatBuiltAt(meta.BuiltAt),
                Path        = path,
                DownloadUrl = downloadUrl,
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
            Path = path,
            CanActivate = false,
            Status = $"{Path.GetFileName(path)}: {reason}",
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

    // Only call this when the local pack is known to match what the server has
    // (an "up to date" outcome). Recording validators for a newer remote that has
    // NOT been applied makes the next check's conditional GET answer 304 "not
    // modified" -- i.e. a pending update would be reported as "up to date" and
    // hidden until the server's file changed again.
    private void RecordValidators(Dictionary<string, PackUpdateRecord> state, string fileName, HttpResponseMessage resp, string localSha)
    {
        var etag = resp.Headers.ETag?.ToString();
        var lastMod = resp.Content.Headers.LastModified?.ToString("o");
        state[fileName] = new PackUpdateRecord
        {
            Etag         = string.IsNullOrEmpty(etag) ? null : etag,
            LastModified = lastMod,
            CheckedAt    = DateTimeOffset.UtcNow.ToString("o"),
            LocalSha     = string.IsNullOrEmpty(localSha) ? null : localSha.ToLowerInvariant(),
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
        if (ClpkFormat.TryReadHeader(ms, out var meta, out _, out _) && !string.IsNullOrEmpty(meta!.Sha))
            return meta.Sha.ToLowerInvariant();
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
        // Validators only count while they were recorded against the pack that is on disk now
        // (see PackUpdateRecord.LocalSha); otherwise fall through to the sha-based check.
        var haveValidators = rec != null
            && !string.IsNullOrEmpty(localSha)
            && string.Equals(rec.LocalSha, localSha, StringComparison.OrdinalIgnoreCase)
            && (!string.IsNullOrEmpty(rec.Etag) || !string.IsNullOrEmpty(rec.LastModified));

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
                RecordValidators(state, fileName, resp, localSha);
                result.Message = "Up to date";
                return result;
            }
            if (resp.IsSuccessStatusCode)
            {
                var bytes = await resp.Content.ReadAsByteArrayAsync();
                var remoteSha = RemoteShaFromBytes(bytes);
                if (!string.IsNullOrEmpty(remoteSha) && !remoteSha.Equals(localSha, StringComparison.OrdinalIgnoreCase))
                {
                    result.UpdateAvailable = true;
                    result.DownloadedBytes = bytes;
                    result.RemoteSha = remoteSha;
                    result.Message = "Update available";
                }
                else
                {
                    RecordValidators(state, fileName, resp, localSha);
                    result.Message = "Up to date";
                }
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
                string remoteSha = "";
                using (var ms = new MemoryStream(headBytes))
                    if (ClpkFormat.TryReadHeader(ms, out var meta, out _, out _) && !string.IsNullOrEmpty(meta!.Sha))
                        remoteSha = meta.Sha.ToLowerInvariant();

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
                if (!result.UpdateAvailable) RecordValidators(state, fileName, resp, localSha);
                result.Message = result.UpdateAvailable ? "Update available" : "Up to date";
                return result;
            }

            if (resp.IsSuccessStatusCode) // server ignored Range; full body returned
            {
                var bytes = await resp.Content.ReadAsByteArrayAsync();
                var remoteSha = RemoteShaFromBytes(bytes);
                if (!string.IsNullOrEmpty(remoteSha) && !remoteSha.Equals(localSha, StringComparison.OrdinalIgnoreCase))
                {
                    result.UpdateAvailable = true;
                    result.DownloadedBytes = bytes;
                    result.RemoteSha = remoteSha;
                    result.Message = "Update available";
                }
                else
                {
                    RecordValidators(state, fileName, resp, localSha);
                    result.Message = "Up to date";
                }
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
            if (ClpkFormat.TryReadHeader(ms, out var meta, out var off, out var len) && !string.IsNullOrEmpty(meta!.Sha))
            {
                using var payload = new SubStream(ms, off, len, leaveOpen: true);
                var actual = ClpkFormat.ComputeSha256Hex(payload);
                if (!actual.Equals(meta.Sha, StringComparison.OrdinalIgnoreCase))
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

        var destPath = Path.Combine(SourceLanguagePacksDir(), entry.FileName);

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
        string author, string language, string downloadUrl)
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

            var meta = new ClpkMetadata
            {
                Author      = author ?? "",
                Language    = language ?? "",
                BuiltAt     = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                DownloadUrl = downloadUrl ?? "",
            };

            using var output = new FileStream(outputClpkPath, FileMode.Create, FileAccess.Write, FileShare.None);
            ClpkFormat.Write(output, zipBytes, meta);
        });
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

        // dragonhook serves every loose file under Game\mods, so the whole payload is extracted.
        var (payload, _) = ClpkFormat.OpenPayload(pack.Path);
        using var _payload = payload;
        using var archive = new ZipArchive(payload, ZipArchiveMode.Read);
        foreach (var entry in archive.Entries)
        {
            var normalizedEntry = NormalizeZipPath(entry.FullName);
            if (string.IsNullOrWhiteSpace(normalizedEntry))
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

    /// <summary>Reads the named packs from the source folder and rebuilds Game\mods from them.
    /// Lets the run/dir-set paths apply the saved active selection without the scanned UI list.</summary>
    public int RebuildGameModsFromActive(string installDir, IEnumerable<string> activeFileNames)
    {
        var packs = activeFileNames
            .Select(fn => Path.Combine(SourceLanguagePacksDir(), fn))
            .Where(File.Exists)
            .Select(ReadLanguagePack)
            .Where(p => p.CanActivate)
            .ToList();
        return RebuildGameModsFolder(installDir, packs);
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
                if (string.IsNullOrWhiteSpace(normalizedEntry))
                    continue;

                ValidateRelativeZipPath(normalizedEntry);

                if (!outputs.TryGetValue(normalizedEntry, out var owners))
                {
                    owners = [];
                    outputs[normalizedEntry] = owners;
                }

                var owner = string.IsNullOrWhiteSpace(pack.LanguageDisplay)
                    ? Path.GetFileName(pack.Path)
                    : pack.LanguageDisplay;
                if (!owners.Contains(owner, StringComparer.OrdinalIgnoreCase))
                    owners.Add(owner);
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


    private static string NormalizeZipPath(string path) =>
        path.Replace('\\', '/').Trim('/');

    private static void ValidateRelativeZipPath(string path)
    {
        if (Path.IsPathRooted(path) || path.Split('/').Any(p => p == ".."))
            throw new InvalidDataException($"Unsafe path in pack metadata: {path}");
    }
}
