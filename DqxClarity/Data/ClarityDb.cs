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

    // Reads every (ja, en) row from a template-shaped table — story_so_far_template
    // or any other two-column ja/en table. Used by PlayerDataMaterializer to pull
    // the generic, placeholder-bearing rows before substituting the current
    // player's specific names/relationship into them.
    public List<(string Ja, string En)> ReadTemplateRows(string table)
    {
        ValidateIdentifier(table);
        var rows = new List<(string, string)>();
        using var conn = Open(readOnly: true);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT ja, en FROM \"{table}\"";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var ja = reader.GetString(0);
            var en = reader.IsDBNull(1) ? "" : reader.GetString(1);
            rows.Add((ja, en));
        }
        return rows;
    }

    // fixed_dialog_template carries a third column marking which rows belong in
    // bad_strings (substring-match overrides) instead of dialog (exact-match cache).
    public List<(string Ja, string En, bool BadString)> ReadFixedDialogTemplate()
    {
        var rows = new List<(string, string, bool)>();
        using var conn = Open(readOnly: true);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT ja, en, bad_string FROM fixed_dialog_template";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var ja = reader.GetString(0);
            var en = reader.IsDBNull(1) ? "" : reader.GetString(1);
            var bad = !reader.IsDBNull(2) && reader.GetInt32(2) != 0;
            rows.Add((ja, en, bad));
        }
        return rows;
    }

    // Wholesale-replaces story_so_far with the given (already placeholder-substituted)
    // rows, in one transaction — mirrors main's "DELETE FROM story_so_far" + bulk
    // INSERT. story_so_far has no upsert story (no unique-key conflict handling
    // needed here) because we're always replacing the entire table for the
    // currently-identified player, not merging into what a previous character left.
    public void ReplaceStorySoFar(IEnumerable<(string Ja, string En)> rows)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        using (var del = conn.CreateCommand())
        {
            del.Transaction = tx;
            del.CommandText = "DELETE FROM story_so_far";
            del.ExecuteNonQuery();
        }
        using (var ins = conn.CreateCommand())
        {
            ins.Transaction = tx;
            ins.CommandText = "INSERT INTO story_so_far (ja, en) VALUES (@ja, @en)";
            var jaParam = ins.Parameters.Add("@ja", SqliteType.Text);
            var enParam = ins.Parameters.Add("@en", SqliteType.Text);
            foreach (var (ja, en) in rows)
            {
                jaParam.Value = ja;
                enParam.Value = en;
                ins.ExecuteNonQuery();
            }
        }
        tx.Commit();
    }

    // Rebuilds bad_strings from scratch and upserts dialog, from the (already
    // placeholder-substituted) fixed_dialog_template rows split by the bad_string
    // flag — mirrors main's "DELETE FROM bad_strings" + "INSERT OR REPLACE INTO
    // dialog/bad_strings". dialog keeps whatever npc_name a previous WriteDialog
    // call set (ON CONFLICT only touches en), same as main leaving that column alone.
    public void ReplaceFixedDialog(IEnumerable<(string Ja, string En, bool BadString)> rows)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        using (var del = conn.CreateCommand())
        {
            del.Transaction = tx;
            del.CommandText = "DELETE FROM bad_strings";
            del.ExecuteNonQuery();
        }
        using var dialogCmd = conn.CreateCommand();
        using var badCmd = conn.CreateCommand();
        dialogCmd.Transaction = tx;
        dialogCmd.CommandText =
            "INSERT INTO dialog (ja, en) VALUES (@ja, @en) " +
            "ON CONFLICT(ja) DO UPDATE SET en = excluded.en";
        var dialogJa = dialogCmd.Parameters.Add("@ja", SqliteType.Text);
        var dialogEn = dialogCmd.Parameters.Add("@en", SqliteType.Text);

        badCmd.Transaction = tx;
        badCmd.CommandText =
            "INSERT INTO bad_strings (ja, en) VALUES (@ja, @en) " +
            "ON CONFLICT(ja) DO UPDATE SET en = excluded.en";
        var badJa = badCmd.Parameters.Add("@ja", SqliteType.Text);
        var badEn = badCmd.Parameters.Add("@en", SqliteType.Text);

        foreach (var (ja, en, bad) in rows)
        {
            if (bad)
            {
                badJa.Value = ja;
                badEn.Value = en;
                badCmd.ExecuteNonQuery();
            }
            else
            {
                dialogJa.Value = ja;
                dialogEn.Value = en;
                dialogCmd.ExecuteNonQuery();
            }
        }
        tx.Commit();
    }

    // Note: there is deliberately no ClarityDb method that rewrites
    // <pnplacehold>/<snplacehold> directly inside m00_strings on disk (main's
    // _update_m00_table does this with a one-way UPDATE ... replace()). That
    // approach is irreversible -- once a token is replaced with one
    // character's name, there's nothing left for a second character
    // (switching mid-session without restarting) to match and replace in
    // turn. See PacketDependencies.ApplyPlayerPlaceholders, which substitutes
    // those two tokens in memory at dict-load time instead, against the
    // never-mutated db row, so every character switch gets a clean pass.

    // Mirrors main's _write_player: replaces the player/sibling/relationship rows
    // for whichever character is now identified as active. Nothing currently reads
    // this table back (see GetPlayerNames' doc note), but we keep it in sync with
    // the schema's intent in case that changes.
    public void WritePlayerRecord(string jaPlayerName, string jaSiblingName, string relationshipKey)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        using (var del = conn.CreateCommand())
        {
            del.Transaction = tx;
            del.CommandText = "DELETE FROM player";
            del.ExecuteNonQuery();
        }
        using (var ins = conn.CreateCommand())
        {
            ins.Transaction = tx;
            ins.CommandText =
                "INSERT INTO player (type, name) VALUES " +
                "('player', @p), ('sibling', @s), ('sibling_relationship', @r)";
            ins.Parameters.AddWithValue("@p", jaPlayerName);
            ins.Parameters.AddWithValue("@s", jaSiblingName);
            ins.Parameters.AddWithValue("@r", relationshipKey);
            ins.ExecuteNonQuery();
        }
        tx.Commit();
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
