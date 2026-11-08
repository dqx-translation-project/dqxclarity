using System.Text;
using DqxClarity.Translation;

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
// NOTE: the field split above is not quite right. The game's text buffer is
// really 280 bytes, and the u32 right after it (payload offset 0x120) is the
// warp destination ID used by the walkthrough's warp button. With the parse
// above, the low byte of that ID lands in unknown_1 and the upper bytes land
// in padding2, so Build() must write every non-text byte back exactly as read.
// Zeroing padding2 sent players to the wrong map for any destination >= 256
// (e.g. 0x016B became 0x006B).
//
// Translates against the `walkthrough` table.
//
// Fit to the walkthrough box: wrapped at 31 characters, at most 3 lines, and
// cut with " [...]" when the English runs over -- the same limits the live
// (main branch) dqxclarity uses for this text. Machine translations are made
// to that shape directly. Text that comes out of the `walkthrough` table is
// re-fitted only if it breaks those limits (see FitToBox): earlier versions of
// this class wrapped machine translations at 46 wide with no line limit and
// cached them, and those old rows would otherwise keep their old shape
// forever; curated rows that already fit are left exactly as they are.
public sealed class WalkthroughPacket : IPacket
{
    private const int FixedBufferBytes = 276; // text bytes + the null terminator
    private const int WrapWidth = 31;
    private const int MaxLines = 3;

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
        writer.WriteBytes(_padding1);
        writer.WriteCString(translated);

        var padBytes = FixedBufferBytes - Encoding.UTF8.GetByteCount(translated);
        if (padBytes > 0) writer.WriteBytes(new byte[padBytes]);

        writer.WriteU32(_unknown1);
        writer.WriteBytes(_padding2); // carries the upper bytes of the warp destination ID
        writer.WriteBytes(_remainder);

        ModifiedData = writer.Build();
    }

    private string? Translate(string original)
    {
        var bad = _deps.Db.SearchBadStrings(original);
        if (bad != null) return bad;

        var cached = _deps.Db.Read(original, "walkthrough");
        if (cached != null) return FitToBox(cached);

        var translated = _deps.Translator.Translate(original, wrapWidth: WrapWidth, maxLines: MaxLines, addBrs: false);
        if (string.IsNullOrEmpty(translated)) return original;

        _deps.Db.Write(original, translated, "walkthrough");
        return translated;
    }

    // Text that already fits (<= 3 lines, none longer than 31 characters) is returned
    // untouched. Otherwise it is re-flowed -- line breaks turned into spaces, then
    // wrapped at 31 with the 3-line limit and " [...]" -- which is what turns a row
    // cached by the old 46-wide wrapping into the right shape.
    private static string FitToBox(string text)
    {
        var lines = text.Split('\n');
        if (lines.Length <= MaxLines && lines.All(l => l.Length <= WrapWidth)) return text;

        var flowed = string.Join(' ', lines.Where(l => l.Length > 0));
        return TextWrapping.Fill(flowed, WrapWidth, MaxLines);
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
