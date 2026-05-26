using System.Text;

namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   num_times_opened     u32
//   padding              4 bytes
//   text                 cstring (utf-8)  -- inside a fixed 277-byte buffer (276 + null)
//   text_padding         (276 - text_byte_len) bytes of 0x00
//   unknown_1            u32
//   padding              4 bytes
//   remainder            (rest of payload)
//
// Translates against the `walkthrough` table.
public sealed class WalkthroughPacket : IPacket
{
    private const int FixedBufferBytes = 276; // text bytes + the null terminator

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private uint _numTimesOpened;
    private byte[] _padding1 = Array.Empty<byte>();
    private string _text = "";
    private uint _unknown1;
    private byte[] _padding2 = Array.Empty<byte>();
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public WalkthroughPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        var reader = new PacketReader(_raw);
        _numTimesOpened = reader.ReadU32();
        _padding1 = reader.ReadBytes(4).ToArray();
        _text = reader.ReadCString();

        var consumed = Encoding.UTF8.GetByteCount(_text);  // null terminator already consumed by ReadCString
        var skip = FixedBufferBytes - consumed;
        if (skip > 0 && reader.Remaining >= skip)
            reader.ReadBytes(skip);

        _unknown1 = reader.ReadU32();
        _padding2 = reader.ReadBytes(4).ToArray();
        _remainder = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var translated = Translate(_text);
        if (translated == null || translated == _text) return;

        // truncate so the utf-8 byte count fits inside 276 bytes (after the null
        // terminator that WriteCString appends, total is at most 277).
        translated = TrimToByteLength(translated, FixedBufferBytes);

        var writer = new PacketWriter();
        writer.WriteU32(_numTimesOpened);
        writer.WriteBytes(new byte[4]);
        writer.WriteCString(translated);

        var padBytes = FixedBufferBytes - Encoding.UTF8.GetByteCount(translated);
        if (padBytes > 0) writer.WriteBytes(new byte[padBytes]);

        writer.WriteU32(_unknown1);
        writer.WriteBytes(new byte[4]);
        writer.WriteBytes(_remainder);

        ModifiedData = writer.Build();
    }

    private string? Translate(string original)
    {
        var bad = _deps.Db.SearchBadStrings(original);
        if (bad != null) return bad;

        var cached = _deps.Db.Read(original, "walkthrough");
        if (cached != null) return cached;

        var translated = _deps.Translator.Translate(original, wrapWidth: 46);
        if (string.IsNullOrEmpty(translated)) return original;

        _deps.Db.Write(original, translated, "walkthrough");
        return translated;
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
