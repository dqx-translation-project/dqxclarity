using System.IO.Compression;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using ClosedXML.Excel;
using DqxClarity.Data;
using DqxClarity.Models;
using Microsoft.Data.Sqlite;

namespace DqxClarity.Updates;

// Downloads two upstream sources and ingests into clarity_dialog.db:
//   1. dqx-custom-translations (zip): json files → m00_strings, merge.xlsx →
//      fixed_dialog_template/walkthrough/quests/story_so_far_template,
//      glossary.csv → glossary, ignore.py → filter to delete from m00_strings
//   2. dqx_translations (json files): six big translation files → m00_strings.
//
// The active language pack can bundle either source (see TranslationConstants):
//   - dqxclarity/json/<name file>.json -- each of the six name files it has is
//     used instead of downloading that file; any it lacks is downloaded.
//   - dqxclarity/custom-translations/ (json/, csv/, optional
//     generate_glossary/ignore.py, same layout as dqx-custom-translations) --
//     when the folder is there, it is the whole of source 1 and nothing is
//     downloaded for it. A part it leaves out (no json, no merge.xlsx, no
//     glossary.csv) is reported and that data is left as it was.
// Without the folder, source 1 comes from the pack's custom translations URL,
// else the default dqx-custom-translations repo.
//
// Uses parameterised inserts inside a single transaction — corrupt input can't escape
// into a sql-injection shape and the failure mode is a clean rollback.
public sealed class TranslationUpdater
{
    private readonly ClarityDb _db;
    private readonly string _dbPath;
    private readonly HttpClient _http;

    public TranslationUpdater(ClarityDb db, string dbPath)
    {
        _db = db;
        _dbPath = dbPath;
        _http = new HttpClient(new HttpClientHandler { AutomaticDecompression = System.Net.DecompressionMethods.All });
    }

    /// <summary>What one update loaded, for the log.</summary>
    public sealed record Result(
        bool CustomTranslationsFromPack,
        int NameFilesFromPack,
        IReadOnlyList<string> Warnings);

    // customTranslationsZipUrl: the dqx-custom-translations-style zip to download
    // when the pack doesn't bundle its custom translations. Null means the default
    // repo; a language pack can name its own (see
    // TranslationConstants.ResolveCustomTranslationsZipUrl).
    // languagePackPath: the active language pack (.clpk), for the files it may
    // bundle, or null for none.
    public async Task<Result> RunAsync(string? customTranslationsZipUrl = null, string? languagePackPath = null,
        CancellationToken ct = default)
    {
        _db.CreateSchema();

        // Read the pack before anything is wiped, so a bad pack changes nothing.
        var packFiles = ReadPackTranslationFiles(languagePackPath);
        var packCustom = ReadPackCustomTranslations(languagePackPath);

        var warnings = new List<string>();
        CustomParts custom;
        if (packCustom != null)
        {
            custom = packCustom;
            const string where = "The language pack's " + TranslationConstants.PackCustomTranslationsFolder + " folder";
            if (custom.Json.Count == 0)
                warnings.Add($"{where} has no json files, so there are no custom translations for them.");
            if (custom.MergeXlsx == null)
                warnings.Add($"{where} has no csv/merge.xlsx; fixed dialogue, walkthrough, quest and story " +
                             "translations from it were not updated.");
            if (custom.GlossaryCsv == null)
                warnings.Add($"{where} has no csv/glossary.csv; the glossary was not updated.");
        }
        else
        {
            var customZip = await _http.GetByteArrayAsync(
                customTranslationsZipUrl ?? TranslationConstants.CustomTranslationsZipUrl, ct).ConfigureAwait(false);
            using var zip = new ZipArchive(new MemoryStream(customZip), ZipArchiveMode.Read);
            custom = CollectCustomParts(zip.Entries.Select(e => (e.FullName, e)), ct);
        }
        await ImportCustomPartsAsync(custom, ct).ConfigureAwait(false);

        var fromPack = 0;
        foreach (var (url, name) in TranslationConstants.TranslationFiles)
        {
            ct.ThrowIfCancellationRequested();
            byte[] data;
            if (packFiles.TryGetValue(TranslationConstants.SourceFileName(url), out var bundled))
            {
                data = bundled;
                fromPack++;
            }
            else
            {
                data = await _http.GetByteArrayAsync(url, ct).ConfigureAwait(false);
            }
            await ImportCustomJsonAsync(name, data, ct).ConfigureAwait(false);
        }
        return new Result(packCustom != null, fromPack, warnings);
    }

    // The dqx-custom-translations parts that get imported, read from a repo zip
    // or from a language pack.
    internal sealed record CustomParts(
        IReadOnlyList<(string Name, byte[] Data)> Json,
        byte[]? MergeXlsx,
        string? GlossaryCsv,
        string? IgnorePy);

    // Picks the parts out of zip entries. Paths are matched the way the repo zip
    // always has been: anything under a json/ folder ending in .json, csv/merge.xlsx,
    // csv/glossary.csv and generate_glossary/ignore.py, at any depth below a
    // leading '/'. Callers pass each entry's path with that leading part.
    private static CustomParts CollectCustomParts(IEnumerable<(string Path, ZipArchiveEntry Entry)> entries,
        CancellationToken ct)
    {
        var json = new List<(string, byte[])>();
        byte[]? merge = null;
        string? glossary = null, ignore = null;

        foreach (var (path, entry) in entries)
        {
            ct.ThrowIfCancellationRequested();
            if (path.EndsWith('/') || string.IsNullOrEmpty(entry.Name)) continue;

            if (path.Contains("/json/") && path.EndsWith(".json"))
                json.Add((Path.GetFileNameWithoutExtension(entry.Name), ReadAll(entry)));
            else if (path.Contains("/csv/") && path.EndsWith("merge.xlsx"))
                merge = ReadAll(entry);
            else if (path.Contains("/csv/") && path.EndsWith("glossary.csv"))
            {
                // StreamReader, as before: it drops a UTF-8 BOM if the file has one.
                using var sr = new StreamReader(new MemoryStream(ReadAll(entry)));
                glossary = sr.ReadToEnd();
            }
            else if (path.Contains("/generate_glossary/") && path.EndsWith("ignore.py"))
                ignore = System.Text.Encoding.UTF8.GetString(ReadAll(entry));
        }
        return new CustomParts(json, merge, glossary, ignore);
    }

    private static byte[] ReadAll(ZipArchiveEntry entry)
    {
        using var s = entry.Open();
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    // Whether a language pack has the custom translations folder at all. Only
    // looks at entry names, so it's cheap.
    internal static bool PackHasCustomTranslations(string? languagePackPath)
    {
        if (string.IsNullOrWhiteSpace(languagePackPath) || !File.Exists(languagePackPath)) return false;
        var prefix = TranslationConstants.PackCustomTranslationsFolder + "/";
        try
        {
            var (payload, _) = ClpkFormat.OpenPayload(languagePackPath);
            using var _payload = payload;
            using var zip = new ZipArchive(payload, ZipArchiveMode.Read);
            return zip.Entries.Any(e =>
                e.FullName.Replace('\\', '/').TrimStart('/').StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    // The custom translations a language pack bundles under
    // TranslationConstants.PackCustomTranslationsFolder; null when the pack has
    // no such folder (or there's no pack, or it can't be read), meaning they are
    // downloaded instead.
    internal static CustomParts? ReadPackCustomTranslations(string? languagePackPath)
    {
        if (string.IsNullOrWhiteSpace(languagePackPath) || !File.Exists(languagePackPath)) return null;
        var prefix = TranslationConstants.PackCustomTranslationsFolder + "/";

        try
        {
            var (payload, _) = ClpkFormat.OpenPayload(languagePackPath);
            using var _payload = payload;
            using var zip = new ZipArchive(payload, ZipArchiveMode.Read);

            var inFolder = new List<(string, ZipArchiveEntry)>();
            var found = false;
            foreach (var entry in zip.Entries)
            {
                var path = entry.FullName.Replace('\\', '/').TrimStart('/');
                if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
                found = true; // the folder exists, even if it turns out empty
                // Keep a leading '/' so "json/x.json" matches "/json/" like the repo zip's paths do.
                inFolder.Add(("/" + path[prefix.Length..], entry));
            }
            return found ? CollectCustomParts(inFolder, CancellationToken.None) : null;
        }
        catch
        {
            return null; // unreadable pack -> download, as before
        }
    }

    // The name files a language pack bundles under TranslationConstants.PackDataFolder,
    // keyed by file name (case-insensitive). Empty for no pack, a pack without
    // them, or a pack that can't be read -- those files are then downloaded.
    internal static Dictionary<string, byte[]> ReadPackTranslationFiles(string? languagePackPath)
    {
        var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(languagePackPath) || !File.Exists(languagePackPath)) return files;

        var wanted = TranslationConstants.TranslationFiles
            .Select(f => TranslationConstants.SourceFileName(f.Url))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var prefix = TranslationConstants.PackDataFolder + "/";

        try
        {
            var (payload, _) = ClpkFormat.OpenPayload(languagePackPath);
            using var _payload = payload;
            using var zip = new ZipArchive(payload, ZipArchiveMode.Read);
            foreach (var entry in zip.Entries)
            {
                var path = entry.FullName.Replace('\\', '/').Trim('/');
                if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
                var name = path[prefix.Length..];
                if (!wanted.Contains(name)) continue; // also skips anything in sub-folders

                using var s = entry.Open();
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                files[name] = ms.ToArray();
            }
        }
        catch
        {
            files.Clear(); // unreadable pack -> download everything, as before
        }
        return files;
    }

    private async Task ImportCustomPartsAsync(CustomParts parts, CancellationToken ct)
    {
        // Wipe + re-ingest m00_strings.
        using (var conn = new SqliteConnection($"Data Source={_dbPath}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM m00_strings";
            cmd.ExecuteNonQuery();
        }

        foreach (var (name, data) in parts.Json)
        {
            ct.ThrowIfCancellationRequested();
            await ImportCustomJsonAsync(name, data, ct).ConfigureAwait(false);
        }

        // A part that isn't there leaves its tables as they are: quests and
        // walkthrough also hold the user's saved machine translations.
        if (parts.MergeXlsx != null)
            ImportMergeXlsx(parts.MergeXlsx);
        if (parts.GlossaryCsv != null)
            ImportGlossary(parts.GlossaryCsv);
        if (parts.IgnorePy != null)
            ApplyIgnoreFilter(parts.IgnorePy);
    }

    // Custom-translations json files are an object of objects: { id: { ja: en }, ... }.
    private Task ImportCustomJsonAsync(string fileName, byte[] data, CancellationToken ct)
    {
        using var doc = JsonDocument.Parse(data);
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO m00_strings (ja, en, file) VALUES (@ja, @en, @file)";
        var pJa = cmd.Parameters.Add("@ja", SqliteType.Text);
        var pEn = cmd.Parameters.Add("@en", SqliteType.Text);
        var pFile = cmd.Parameters.Add("@file", SqliteType.Text);
        pFile.Value = fileName;

        foreach (var item in doc.RootElement.EnumerateObject())
        {
            // value is { ja: en } — single entry per item; take the first pair only
            if (item.Value.ValueKind != JsonValueKind.Object) continue;
            foreach (var pair in item.Value.EnumerateObject())
            {
                pJa.Value = pair.Name;
                pEn.Value = pair.Value.GetString() ?? "";
                cmd.ExecuteNonQuery();
                break;
            }
        }
        tx.Commit();
        return Task.CompletedTask;
    }

    private void ImportMergeXlsx(byte[] xlsxBytes)
    {
        using var wb = new XLWorkbook(new MemoryStream(xlsxBytes));

        ImportDialogueSheet(wb.Worksheet("Dialogue"));
        ImportSimpleSheet(wb.Worksheet("Walkthrough"), "walkthrough");
        ImportSimpleSheet(wb.Worksheet("Quests"), "quests");
        ImportStorySoFarSheet(wb.Worksheet("Story So Far"));
    }

    private void ImportDialogueSheet(IXLWorksheet ws)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        using var tx = conn.BeginTransaction();

        using (var del = conn.CreateCommand())
        {
            del.Transaction = tx;
            del.CommandText = "DELETE FROM fixed_dialog_template";
            del.ExecuteNonQuery();
        }

        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText =
            "INSERT OR REPLACE INTO fixed_dialog_template (ja, en, bad_string) VALUES (@ja, @en, @bad)";
        var pJa = cmd.Parameters.Add("@ja", SqliteType.Text);
        var pEn = cmd.Parameters.Add("@en", SqliteType.Text);
        var pBad = cmd.Parameters.Add("@bad", SqliteType.Integer);

        foreach (var row in ws.RowsUsed().Skip(1))
        {
            var source = row.Cell(1).GetString();
            var en = row.Cell(3).GetString();
            var notes = row.Cell(4).GetString();
            var origBad = row.Cell(5).GetString();

            if (string.IsNullOrEmpty(source) || string.IsNullOrEmpty(en)) continue;

            var bad = 0;
            if (!string.IsNullOrEmpty(notes) && notes.Contains("BAD STRING", StringComparison.Ordinal))
            {
                if (string.IsNullOrEmpty(origBad)) bad = 1;
                else source = origBad;
            }

            pJa.Value = source;
            pEn.Value = en;
            pBad.Value = bad;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    private void ImportSimpleSheet(IXLWorksheet ws, string tableName)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = $"INSERT OR REPLACE INTO \"{tableName}\" (ja, en) VALUES (@ja, @en)";
        var pJa = cmd.Parameters.Add("@ja", SqliteType.Text);
        var pEn = cmd.Parameters.Add("@en", SqliteType.Text);

        foreach (var row in ws.RowsUsed().Skip(1))
        {
            var source = row.Cell(1).GetString();
            var en = row.Cell(3).GetString();
            if (string.IsNullOrEmpty(source) || string.IsNullOrEmpty(en)) continue;
            pJa.Value = source;
            pEn.Value = en;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    private void ImportStorySoFarSheet(IXLWorksheet ws)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT OR REPLACE INTO story_so_far_template (ja, en) VALUES (@ja, @en)";
        var pJa = cmd.Parameters.Add("@ja", SqliteType.Text);
        var pEn = cmd.Parameters.Add("@en", SqliteType.Text);

        foreach (var row in ws.RowsUsed().Skip(1))
        {
            var source = row.Cell(1).GetString();
            var deepl  = row.Cell(2).GetString();
            var fixedEn = row.Cell(3).GetString();
            if (string.IsNullOrEmpty(source)) continue;

            string en;
            if (!string.IsNullOrEmpty(fixedEn))      en = fixedEn;
            else if (!string.IsNullOrEmpty(deepl))   en = deepl;
            else continue;

            pJa.Value = source;
            pEn.Value = en;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    // csv format is `ja,en` (en may contain commas).
    private void ImportGlossary(string csvText)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        using var tx = conn.BeginTransaction();
        using (var del = conn.CreateCommand())
        {
            del.Transaction = tx;
            del.CommandText = "DELETE FROM glossary";
            del.ExecuteNonQuery();
        }
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT OR REPLACE INTO glossary (ja, en) VALUES (@ja, @en)";
        var pJa = cmd.Parameters.Add("@ja", SqliteType.Text);
        var pEn = cmd.Parameters.Add("@en", SqliteType.Text);

        foreach (var line in csvText.Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var idx = line.IndexOf(',');
            if (idx < 0) continue;
            pJa.Value = line[..idx];
            pEn.Value = line[(idx + 1)..].TrimEnd('\r');
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    // Parses the ignore file with a regex looking for `IGNORE = { ... }` and extracts keys to delete.
    private void ApplyIgnoreFilter(string ignorePyText)
    {
        var match = Regex.Match(ignorePyText, @"IGNORE\s*=\s*\{(.*?)\}", RegexOptions.Singleline);
        if (!match.Success) return;

        var body = match.Groups[1].Value;
        var keys = new List<string>();
        foreach (Match keyMatch in Regex.Matches(body, @"['""]([^'""]+)['""]\s*:"))
            keys.Add(keyMatch.Groups[1].Value);

        if (keys.Count == 0) return;

        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        var placeholders = string.Join(",", keys.Select((_, i) => $"@k{i}"));
        cmd.CommandText = $"DELETE FROM m00_strings WHERE ja IN ({placeholders})";
        for (var i = 0; i < keys.Count; i++)
            cmd.Parameters.AddWithValue($"@k{i}", keys[i]);
        cmd.ExecuteNonQuery();
        tx.Commit();
    }
}
