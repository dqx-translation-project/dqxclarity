using DqxClarity.Models;
using Microsoft.Data.Sqlite;

namespace DqxClarity.Services;

public class DatabaseService
{
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

    private string DbPath()
    {
        var dir = FindAppDir(ExeDir());
        return Path.Combine(dir, "misc_files", "clarity_dialog.db");
    }

    private static void ValidateIdentifier(string name)
    {
        if (!name.All(c => char.IsLetterOrDigit(c) || c == '_'))
            throw new Exception($"Invalid identifier: {name}");
    }

    public List<string> ReadTables()
    {
        var path = DbPath();
        if (!File.Exists(path)) throw new FileNotFoundException("misc_files/clarity_dialog.db not found");

        var tables = new List<string>();
        using var conn = new SqliteConnection($"Data Source={path};Mode=ReadOnly");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name";
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) tables.Add(reader.GetString(0));
        return tables;
    }

    public DbTableData ReadTable(string table)
    {
        ValidateIdentifier(table);
        var path = DbPath();
        using var conn = new SqliteConnection($"Data Source={path};Mode=ReadOnly");
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT rowid, * FROM \"{table}\"";
        using var reader = cmd.ExecuteReader();

        var columns = new List<string>();
        for (int i = 1; i < reader.FieldCount; i++)
            columns.Add(reader.GetName(i));

        var rows = new List<DbRow>();
        while (reader.Read())
        {
            var rowId = reader.GetInt64(0);
            var values = new List<string?>();
            for (int i = 1; i < reader.FieldCount; i++)
                values.Add(reader.IsDBNull(i) ? null : reader.GetString(i));
            rows.Add(new DbRow { RowId = rowId, Values = values });
        }

        return new DbTableData { Columns = columns, Rows = rows };
    }

    public void DeleteRows(string table, IEnumerable<long> rowIds)
    {
        var ids = rowIds.ToList();
        if (ids.Count == 0) return;
        ValidateIdentifier(table);

        var path = DbPath();
        using var conn = new SqliteConnection($"Data Source={path}");
        conn.Open();

        var placeholders = string.Join(",", ids.Select((_, i) => $"@p{i}"));
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"DELETE FROM \"{table}\" WHERE rowid IN ({placeholders})";
        for (int i = 0; i < ids.Count; i++)
            cmd.Parameters.AddWithValue($"@p{i}", ids[i]);
        cmd.ExecuteNonQuery();
    }

    public void PurgeDialogCache()
    {
        var path = DbPath();
        if (!File.Exists(path)) throw new FileNotFoundException("misc_files/clarity_dialog.db not found");
        using var conn = new SqliteConnection($"Data Source={path}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM dialog";
        cmd.ExecuteNonQuery();
    }
}
