using System.Reflection;
using System.Text;
using Microsoft.Data.Sqlite;

namespace DqxClarity.Data;

// Translation pipeline data access for clarity_dialog.db. Uses parameterised queries
// throughout — same semantics as raw string concatenation, no injection footgun.
public sealed class ClarityDb
{
    private readonly string _dbPath;

    public ClarityDb(string dbPath)
    {
        _dbPath = dbPath;
    }

    public static string DefaultDbPath()
    {
        var exe = Environment.ProcessPath ?? AppContext.BaseDirectory;
        var dir = Path.GetDirectoryName(exe) ?? AppContext.BaseDirectory;
        return Path.Combine(dir, "misc_files", "clarity_dialog.db");
    }

    private SqliteConnection Open(bool readOnly = false)
    {
        var cs = readOnly
            ? $"Data Source={_dbPath};Mode=ReadOnly"
            : $"Data Source={_dbPath}";
        var conn = new SqliteConnection(cs);
        conn.Open();
        return conn;
    }

    public void CreateSchema()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_dbPath)!);
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = LoadEmbeddedSchema();
        cmd.ExecuteNonQuery();
    }

    private static string LoadEmbeddedSchema()
    {
        var asm = Assembly.GetExecutingAssembly();
        using var stream = asm.GetManifestResourceStream("DqxClarity.Data.schema.sql")
            ?? throw new InvalidOperationException("Embedded schema.sql not found");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    public string? Read(string ja, string table, bool wildcard = false)
    {
        ValidateIdentifier(table);
        using var conn = Open(readOnly: true);
        using var cmd = conn.CreateCommand();
        if (wildcard)
        {
            // replace newlines with % then wrap in %…% for substring wildcard matching
            var pattern = "%" + ja.Replace("\n", "%") + "%";
            cmd.CommandText = $"SELECT en FROM \"{table}\" WHERE ja LIKE @p";
            cmd.Parameters.AddWithValue("@p", pattern);
        }
        else
        {
            cmd.CommandText = $"SELECT en FROM \"{table}\" WHERE ja = @p";
            cmd.Parameters.AddWithValue("@p", ja);
        }
        var result = cmd.ExecuteScalar();
        return result is null or DBNull ? null : (string)result;
    }

    public void Write(string ja, string en, string table)
    {
        ValidateIdentifier(table);
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText =
            $"INSERT INTO \"{table}\" (ja, en) VALUES (@ja, @en) " +
            "ON CONFLICT(ja) DO UPDATE SET en = excluded.en";
        cmd.Parameters.AddWithValue("@ja", ja);
        cmd.Parameters.AddWithValue("@en", en);
        cmd.ExecuteNonQuery();
    }

    // in-text substring check: returns the en translation if any bad_strings ja key appears in `text`.
    public string? SearchBadStrings(string text)
    {
        using var conn = Open(readOnly: true);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT ja, en FROM bad_strings";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var ja = reader.GetString(0);
            if (text.Contains(ja, StringComparison.Ordinal))
                return reader.IsDBNull(1) ? null : reader.GetString(1);
        }
        return null;
    }

    // Sort by utf-8 byte length of the key (up to the first comma if present), descending.
    // The longest-first ordering is load-bearing for terminology consistency.
    public List<KeyValuePair<string, string>> LoadGlossarySortedLongestFirst()
    {
        var rows = new List<KeyValuePair<string, string>>();
        using var conn = Open(readOnly: true);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT ja, en FROM glossary";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var ja = reader.GetString(0);
            var en = reader.IsDBNull(1) ? "" : reader.GetString(1);
            rows.Add(new(ja, en));
        }

        return rows
            .OrderByDescending(r => Encoding.UTF8.GetByteCount(KeyHead(r.Key)))
            .ToList();

        static string KeyHead(string s)
        {
            var idx = s.IndexOf(',');
            return idx < 0 ? s : s[..idx];
        }
    }

    public Dictionary<string, string> LoadM00Strings(IReadOnlyList<string>? files = null)
    {
        var data = new Dictionary<string, string>();
        using var conn = Open(readOnly: true);
        using var cmd = conn.CreateCommand();
        if (files is { Count: > 0 })
        {
            var placeholders = string.Join(",", Enumerable.Range(0, files.Count).Select(i => $"@f{i}"));
            cmd.CommandText = $"SELECT ja, en FROM m00_strings WHERE file IN ({placeholders})";
            for (var i = 0; i < files.Count; i++)
                cmd.Parameters.AddWithValue($"@f{i}", files[i]);
        }
        else
        {
            cmd.CommandText = "SELECT ja, en FROM m00_strings";
        }
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var ja = reader.GetString(0);
            var en = reader.IsDBNull(1) ? "" : reader.GetString(1);
            data[ja] = en;
        }
        return data;
    }

    // Insert-or-update with an explicit npc_name column. Used by NpcDialoguePacket.
    public void WriteDialog(string ja, string en, string npcName)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "INSERT INTO dialog (ja, npc_name, en) VALUES (@ja, @npc, @en) " +
            "ON CONFLICT(ja) DO UPDATE SET en = excluded.en, npc_name = excluded.npc_name";
        cmd.Parameters.AddWithValue("@ja", ja);
        cmd.Parameters.AddWithValue("@npc", npcName);
        cmd.Parameters.AddWithValue("@en", en);
        cmd.ExecuteNonQuery();
    }

    // Returns ("", "") if either row is missing so callers can short-circuit rather than throwing.
    public (string Player, string Sibling) GetPlayerNames()
    {
        string player = "", sibling = "";
        using var conn = Open(readOnly: true);
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT name FROM player WHERE type = 'player' LIMIT 1";
            var r = cmd.ExecuteScalar();
            if (r is string s) player = s;
        }
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT name FROM player WHERE type = 'sibling' LIMIT 1";
            var r = cmd.ExecuteScalar();
            if (r is string s) sibling = s;
        }
        return (player, sibling);
    }

    private static void ValidateIdentifier(string name)
    {
        // mirrors DatabaseService.ValidateIdentifier — guard the small set of table
        // names we ever pass in dynamically.
        foreach (var c in name)
            if (!char.IsLetterOrDigit(c) && c != '_')
                throw new ArgumentException($"Invalid table name: {name}");
    }
}
