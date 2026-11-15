using System.Text;

namespace DqxClarity.Packets.Types;

//

// Same shape as MemoryListChaptersPacket but with one extra u32 per entry and
// only a single list section. Names looked up in m00 'story_names'; misses pass through.
//
// Layout (after opcode + marker):
//   num_times_opened  u32
//   padding           4 bytes
//   num_subchapters   u32
//   subchapters[]     { u32, u32, name cstring }
//
// Same strict parse and copy-through rebuild as MemoryListChaptersPacket: the
// last name must end exactly at the end of the packet, only translated names
// are rewritten (cut to 29 bytes), and nothing is sent back if none changed.
public sealed class MemoryListSubChaptersPacket : IPacket
{
    private const int HeaderBytes = 8;       // num_times_opened + padding
    private const int MaxChapterBytes = 29;
    private const int MaxEntries = 512;
    private const int MaxNameBytes = 1024;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MemoryListSubChaptersPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        var reader = new PacketReader(_raw);
        reader.ReadBytesStrict(HeaderBytes, "memory sub-chapter header");

        var names = new List<(int Start, int Length, string Text)>();
        var count = reader.ReadCountStrict("sub-chapter count", MaxEntries);
        for (var i = 0; i < count; i++)
        {
            reader.ReadBytesStrict(8, $"sub-chapter {i + 1} ids");
            var start = reader.Position;
            var name = reader.ReadCStringStrict($"sub-chapter {i + 1} name", MaxNameBytes);
            names.Add((start, reader.Position - 1 - start, name));
        }
        reader.ExpectEnd("memory sub-chapter list");

        var dict = _deps.M00Dict("story_names");
        var patch = new PacketPatch(_raw);
        foreach (var (start, length, text) in names)
        {
            if (text.Length == 0) continue;
            if (!dict.TryGetValue(text, out var en) || string.IsNullOrEmpty(en) || en == text) continue;
            patch.ReplaceText(start, length, PacketPatch.TruncateUtf8(en, MaxChapterBytes));
        }

        if (patch.HasEdits) ModifiedData = patch.Build();
    }
}
