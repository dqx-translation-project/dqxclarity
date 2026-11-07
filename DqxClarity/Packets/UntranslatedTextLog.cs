using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DqxClarity.Packets;

// Collects japanese lines that had no translation, in a form that can be
// pasted straight into one of the custom json files. Each new line is
// appended to the log file as
//
// "1": {
//     "<japanese text>": ""
//   },
//
// -- the key is a running number (continuing from whatever the file already
// holds), the text is json-escaped but left readable, and the translation is
// left empty to fill in. The trailing comma is there so entries can be pasted
// between others; drop it on the last one in the file.
//
// Each distinct line is written once: lines already in the file (from an
// earlier session) are not written again, so the file doesn't fill up with
// repeats while a line is still waiting to be translated. Delete the file (or
// the entries you have dealt with) to start over. Recording never throws.
public sealed class UntranslatedTextLog
{
    private static readonly JsonSerializerOptions Json = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly Regex EntryStart = new(@"^""(\d+)"": \{", RegexOptions.Compiled);
    private static readonly Regex EntryText = new(@"^\s+(""(?:[^""\\]|\\.)*""):", RegexOptions.Compiled);

    private readonly string _path;
    private readonly object _gate = new();
    private readonly HashSet<string> _seen = new();
    private int _next = 1;
    private bool _loaded;

    public UntranslatedTextLog(string path)
    {
        _path = path;
    }

    public void Record(string japanese)
    {
        if (string.IsNullOrWhiteSpace(japanese)) return;

        try
        {
            var key = JsonSerializer.Serialize(japanese, Json);
            lock (_gate)
            {
                if (!_loaded) Load();
                if (!_seen.Add(key)) return;

                var entry = $"\"{_next}\": {{{Environment.NewLine}    {key}: \"\"{Environment.NewLine}  }},{Environment.NewLine}";
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                File.AppendAllText(_path, entry, new UTF8Encoding(false));
                _next++;
            }
        }
        catch
        {
            // A log that can't be written must never affect a packet.
        }
    }

    // Reads what an earlier session left in the file: the texts already
    // there and the next entry number.
    private void Load()
    {
        _loaded = true;
        if (!File.Exists(_path)) return;

        var highest = 0;
        foreach (var line in File.ReadLines(_path, Encoding.UTF8))
        {
            var start = EntryStart.Match(line);
            if (start.Success && int.TryParse(start.Groups[1].Value, out var n) && n > highest) highest = n;

            var text = EntryText.Match(line);
            if (text.Success) _seen.Add(text.Groups[1].Value);
        }
        _next = highest + 1;
    }
}
