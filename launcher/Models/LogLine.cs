namespace DqxClarity.Launcher.Models;

/// <summary>A single contiguous span of text with an optional ANSI foreground color.</summary>
public record AnsiRun(string Text, string? HexColor = null);

public class LogLine
{
    public string Level { get; init; } = "info"; // "info" | "error"
    public string Text  { get; init; } = "";     // plain text (ANSI stripped)

    /// <summary>Colored segments parsed from ANSI escape codes. Empty = use Level brush.</summary>
    public IReadOnlyList<AnsiRun> Runs { get; init; } = [];
}

public record UpdateInfo(string Version, string Body);

public class DbRow
{
    public long RowId { get; init; }
    public List<string?> Values { get; init; } = [];
    public bool Selected { get; set; }
}

public class DbTableData
{
    public List<string> Columns { get; init; } = [];
    public List<DbRow> Rows { get; init; } = [];
}
