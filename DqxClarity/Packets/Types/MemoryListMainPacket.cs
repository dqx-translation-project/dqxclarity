using System.Text;

namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   header_data  12 bytes (passthrough)
//   text_list    null-separated utf-8 strings, all concatenated
//
// Each string is looked up in m00 'story_names'; misses pass through. Strings are
// capped at 29 utf-8 bytes — the game's memory window locks up otherwise.
public sealed class MemoryListMainPacket : IPacket
{
    private const int HeaderBytes = 12;
    private const int MaxChapterBytes = 29;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private List<string> _textList = new();

    public byte[]? ModifiedData { get; private set; }

    public MemoryListMainPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes) return;
        _header = _raw.AsSpan(0, HeaderBytes).ToArray();

        var rest = _raw.AsSpan(HeaderBytes).ToArray();
        var parts = new List<string>();
        var start = 0;
        for (var i = 0; i < rest.Length; i++)
        {
            if (rest[i] == 0)
            {
                if (i > start) parts.Add(Encoding.UTF8.GetString(rest, start, i - start));
                start = i + 1;
            }
        }
        // trailing non-null tail
        if (start < rest.Length) parts.Add(Encoding.UTF8.GetString(rest, start, rest.Length - start));
        _textList = parts;
    }

    public void Build()
    {
        if (_textList.Count == 0) return;
        var dict = _deps.M00Dict("story_names");

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        foreach (var s in _textList)
        {
            var translated = dict.GetValueOrDefault(s, s);
            writer.WriteCString(TruncateUtf8(translated, MaxChapterBytes));
        }
        ModifiedData = writer.Build();
    }

    private static string TruncateUtf8(string s, int maxBytes)
    {
        var bytes = Encoding.UTF8.GetByteCount(s);
        if (bytes <= maxBytes) return s;
        var sb = new StringBuilder();
        var running = 0;
        foreach (var c in s)
        {
            var cb = Encoding.UTF8.GetByteCount(new[] { c });
            if (running + cb > maxBytes) break;
            sb.Append(c);
            running += cb;
        }
        return sb.ToString();
    }
}
