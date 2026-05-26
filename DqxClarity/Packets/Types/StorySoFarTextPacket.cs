using System.Text;

namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   num_times_opened     u32
//   padding              4 bytes
//   text                 cstring (utf-8) — must fit in a 517-byte slot
//   remainder            (discarded on rewrite)
//
// The total packet must not exceed 531 bytes (including the opcode+marker+size
// header added by outer layers). We cap the translated text at 516 bytes; the
// null terminator brings that to 517 inside the fixed slot.
public sealed class StorySoFarTextPacket : IPacket
{
    private const int MaxTextBytes = 516;
    private const int FixedTextBlockBytes = 516; // bytes available after the cstring's null

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private uint _numTimesOpened;
    private string _text = "";

    public byte[]? ModifiedData { get; private set; }

    public StorySoFarTextPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        var reader = new PacketReader(_raw);
        _numTimesOpened = reader.ReadU32();
        reader.ReadBytes(4); // padding
        _text = reader.ReadCString();
    }

    public void Build()
    {
        var translated = Lookup(_text);
        if (translated == null || translated == _text) return;

        var clipped = TrimToByteLength(translated, MaxTextBytes);
        var byteLen = Encoding.UTF8.GetByteCount(clipped);

        var writer = new PacketWriter();
        writer.WriteU32(_numTimesOpened);
        writer.WriteBytes(new byte[4]);
        writer.WriteCString(clipped);

        var pad = FixedTextBlockBytes - byteLen;
        if (pad > 0) writer.WriteBytes(new byte[pad]);

        ModifiedData = writer.Build();
    }

    // Cache-only lookup: bad_strings + story_so_far tables. We deliberately do
    // NOT call the backend translator here — story-so-far text is long-form
    // recap content that doesn't survive machine translation well, and it
    // refers heavily to characters and locations that need hand-curated
    // wording to stay consistent with the rest of the en localization. When
    // the db misses we return the original japanese so the game renders the
    // untranslated text instead of garbled MT output.
    private string? Lookup(string original)
    {
        var bad = _deps.Db.SearchBadStrings(original);
        if (bad != null) return bad;

        var cached = _deps.Db.Read(original, "story_so_far");
        if (cached != null) return cached;

        return original;
    }

    private static string TrimToByteLength(string s, int maxBytes)
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
