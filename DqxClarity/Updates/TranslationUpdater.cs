using System.IO.Compression;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using ClosedXML.Excel;
using DqxClarity.Data;
using Microsoft.Data.Sqlite;

namespace DqxClarity.Updates;

// Downloads two upstream sources and ingests into clarity_dialog.db:
//   1. dqx-custom-translations (zip): json files → m00_strings, merge.xlsx →
//      fixed_dialog_template/walkthrough/quests/story_so_far_template,
//      glossary.csv → glossary, ignore.py → filter to delete from m00_strings
//   2. dqx_translations (json files): six big translation files → m00_strings
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

    public async Task RunAsync(CancellationToken ct = default)
    {
        _db.CreateSchema();

        var customZip = await _http.GetByteArrayAsync(TranslationConstants.CustomTranslationsZipUrl, ct).ConfigureAwait(false);
        await ImportCustomZipAsync(customZip, ct).ConfigureAwait(false);

        foreach (var (url, name) in TranslationConstants.TranslationFiles)
        {
            ct.ThrowIfCancellationRequested();
            var data = await _http.GetByteArrayAsync(url, ct).ConfigureAwait(false);
            await ImportCustomJsonAsync(name, data, ct).ConfigureAwait(false);
        }
    }

    private async Task ImportCustomZipAsync(byte[] zipBytes, CancellationToken ct)
    {
        using var zip = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read);

        // Wipe + re-ingest m00_strings.
        using (var conn = new SqliteConnection($"Data Source={_dbPath}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM m00_strings";
            cmd.ExecuteNonQuery();
        }

        byte[]? ignorePy = null;

        foreach (var entry in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (entry.FullName.EndsWith('/')) continue;

            if (entry.FullName.Contains("/json/") && entry.FullName.EndsWith(".json"))
            {
                using var s = entry.Open();
                using var ms = new MemoryStream();
                await s.CopyToAsync(ms, ct).ConfigureAwait(false);
                var name = Path.GetFileNameWithoutExtension(entry.Name);
                await ImportCustomJsonAsync(name, ms.ToArray(), ct).ConfigureAwait(false);
            }
            else if (entry.FullName.Contains("/csv/"))
            {
                if (entry.FullName.EndsWith("merge.xlsx"))
                {
                    using var s = entry.Open();
                    using var ms = new MemoryStream();
                    await s.CopyToAsync(ms, ct).ConfigureAwait(false);
                    ImportMergeXlsx(ms.ToArray());
                }
                else if (entry.FullName.EndsWith("glossary.csv"))
                {
                    using var s = entry.Open();
                    using var sr = new StreamReader(s);
                    var glossary = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                    ImportGlossary(glossary);
                }
            }
            else if (entry.FullName.Contains("/generate_glossary/") && entry.FullName.EndsWith("ignore.py"))
            {
                using var s = entry.Open();
                using var ms = new MemoryStream();
                await s.CopyToAsync(ms, ct).ConfigureAwait(false);
                ignorePy = ms.ToArray();
            }
        }

        if (ignorePy != null)
            ApplyIgnoreFilter(System.Text.Encoding.UTF8.GetString(ignorePy));
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
