using System.Text;

namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   num_times_opened     u32
//   padding              4 bytes
//   num_chapters         u32
//   chapters[num_chapters]: { unknown u32, name cstring }
//   num_stories          u32
//   stories[num_stories]:  { unknown u32, name cstring }
//
// All names looked up in m00 'story_names'; misses pass through. Empty names
// re-emitted as a single 0x00 byte.
public sealed class MemoryListChaptersPacket : IPacket
{
    private const int MaxChapterBytes = 29;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private uint _numTimesOpened;
    private byte[] _padding = Array.Empty<byte>();
    private uint _numChapters;
    private uint _numStories;
    private readonly List<(uint Val, string Name)> _chapters = new();
    private readonly List<(uint Val, string Name)> _stories = new();

    public byte[]? ModifiedData { get; private set; }

    public MemoryListChaptersPacket(byte[] payloadData, PacketDependencies deps)
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
        _numChapters = reader.ReadU32();
        for (var i = 0; i < _numChapters; i++)
        {
            var v = reader.ReadU32();
            var n = reader.ReadCString();
            _chapters.Add((v, n));
        }
        _numStories = reader.ReadU32();
        for (var i = 0; i < _numStories; i++)
        {
            var v = reader.ReadU32();
            var n = reader.ReadCString();
            _stories.Add((v, n));
        }
    }

    public void Build()
    {
        if (_chapters.Count == 0 && _stories.Count == 0) return;
        var dict = _deps.M00Dict("story_names");

        var writer = new PacketWriter();
        writer.WriteU32(_numTimesOpened);
        writer.WriteBytes(_padding);
        writer.WriteU32(_numChapters);
        foreach (var (val, name) in _chapters)
        {
            writer.WriteU32(val);
            EmitName(writer, dict, name);
        }
        writer.WriteU32(_numStories);
        foreach (var (val, name) in _stories)
        {
            writer.WriteU32(val);
            EmitName(writer, dict, name);
        }
        ModifiedData = writer.Build();
    }

    private static void EmitName(PacketWriter writer, IReadOnlyDictionary<string, string> dict, string name)
    {
        if (string.IsNullOrEmpty(name)) { writer.WriteU8(0); return; }
        var translated = dict.GetValueOrDefault(name, name);
        writer.WriteCString(TruncateUtf8(translated, MaxChapterBytes));
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
