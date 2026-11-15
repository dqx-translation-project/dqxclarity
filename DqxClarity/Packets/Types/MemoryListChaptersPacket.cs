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
// All names looked up in m00 'story_names'; misses pass through untouched.
//
// The parse is strict: both counts must be present and the last story name
// must end exactly at the end of the packet, otherwise PacketLayoutException
// makes PacketGuard pass the original through and file a mismatch report.
// Only names that are actually translated are rewritten (cut to 29 bytes);
// everything else is copied byte-for-byte, and nothing is sent back at all
// when no name changed. (An earlier version rebuilt the packet every time and
// cut EVERY name to 29 bytes -- including untranslated Japanese titles such
// as エテーネの村のおはなし, 33 bytes -- so it changed the packet even when
// there was nothing to translate.)
public sealed class MemoryListChaptersPacket : IPacket
{
    private const int HeaderBytes = 8;       // num_times_opened + padding
    private const int MaxChapterBytes = 29;
    private const int MaxEntries = 512;
    private const int MaxNameBytes = 1024;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MemoryListChaptersPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        var reader = new PacketReader(_raw);
        reader.ReadBytesStrict(HeaderBytes, "memory list header");

        var names = new List<(int Start, int Length, string Text)>();
        foreach (var section in new[] { "chapter", "story" })
        {
            var count = reader.ReadCountStrict($"{section} count", MaxEntries);
            for (var i = 0; i < count; i++)
            {
                reader.ReadU32Strict($"{section} {i + 1} id");
                var start = reader.Position;
                var name = reader.ReadCStringStrict($"{section} {i + 1} name", MaxNameBytes);
                names.Add((start, reader.Position - 1 - start, name));
            }
        }
        reader.ExpectEnd("memory list");

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
