using System.Text;

namespace DqxClarity.Packets.Types;

//

// Same shape as MemoryListChaptersPacket but with one extra u32 per entry and
// only a single list section. Names looked up in m00 'story_names'; misses pass through.
public sealed class MemoryListSubChaptersPacket : IPacket
{
    private const int MaxChapterBytes = 29;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private uint _numTimesOpened;
    private byte[] _padding = Array.Empty<byte>();
    private uint _numSubChapters;
    private readonly List<(uint U1, uint U2, string Name)> _subChapters = new();

    public byte[]? ModifiedData { get; private set; }

    public MemoryListSubChaptersPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        var reader = new PacketReader(_raw);
        _numTimesOpened = reader.ReadU32();
        _padding = reader.ReadBytes(4).ToArray();
        _numSubChapters = reader.ReadU32();
        for (var i = 0; i < _numSubChapters; i++)
        {
            var u1 = reader.ReadU32();
            var u2 = reader.ReadU32();
            var n = reader.ReadCString();
            _subChapters.Add((u1, u2, n));
        }
    }

    public void Build()
    {
        if (_subChapters.Count == 0) return;
        var dict = _deps.M00Dict("story_names");

        var writer = new PacketWriter();
        writer.WriteU32(_numTimesOpened);
        writer.WriteBytes(_padding);
        writer.WriteU32(_numSubChapters);
        foreach (var (u1, u2, name) in _subChapters)
        {
            writer.WriteU32(u1);
            writer.WriteU32(u2);
            if (string.IsNullOrEmpty(name)) writer.WriteU8(0);
            else
            {
                var translated = dict.GetValueOrDefault(name, name);
                writer.WriteCString(TruncateUtf8(translated, MaxChapterBytes));
            }
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
