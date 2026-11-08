using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The "story so far" recap text. Two packets carry it, with the same text and
// the same translation, shown in the same recap window:
//
//   Variant.Window  (0x21 0xbe01) -- opened normally
//   Variant.Map     (0x5c 0x131e) -- opened from the map
//
// Layout of the Window variant (after opcode + marker):
//   num_times_opened     u32
//   padding              4 bytes
//   text                 cstring (utf-8) — must fit in a 517-byte slot
//   remainder            (discarded on rewrite)
//
// Layout of the Map variant (after opcode + marker), from one capture (423
// bytes of Data):
//   header               28 bytes -- passthrough (8 zero bytes, a u32 7C, a
//                        constant-looking 62 22 20 01, then 03 07 00 00;
//                        meaning unknown, probably a story/chapter id). There
//                        is no length field in it.
//   text                 cstring (utf-8, lines separated by 0A) running to
//                        the end of the packet: unlike the Window variant it
//                        is NOT padded out to a fixed slot (the capture ends
//                        at the null terminator), so the translation is
//                        written as a plain cstring, with no padding.
//   remainder            (kept, empty in the capture)
// The text is capped at the same 516 bytes (the recap window's buffer), and a
// header or text that is not what this expects is left untouched and reported
// (PacketLayoutException).
//
// Samples: docs/packets/references/storysofar (Window),
//          storysofar_map (Map)
//
// The total packet must not exceed 531 bytes (including the opcode+marker+size
// header added by outer layers). We cap the translated text at 516 bytes; the
// null terminator brings that to 517 inside the fixed slot.
//
// Translation path (same shape as QuestPacket's description): bad_strings ->
// story_so_far db rows -> machine translation, wrapped to 43 characters per
// line and 8 lines with no <br> injection. See TranslateText.
public sealed class StorySoFarTextPacket : IPacket
{
    private const int MaxTextBytes = 516;
    private const int FixedTextBlockBytes = 516; // bytes available after the cstring's null

    // Recap window layout, used for machine translation wrapping.
    private const int WrapWidth = 43; // characters per line
    private const int MaxLines = 8;

    public enum Variant { Window, Map }
    private const int MapHeaderBytes = 28;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private readonly Variant _variant;
    private uint _numTimesOpened;
    private string _text = "";
    private byte[] _mapHeader = Array.Empty<byte>();
    private byte[] _mapRemainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public StorySoFarTextPacket(byte[] payloadData, PacketDependencies deps, Variant variant = Variant.Window)
    {
        _raw = payloadData;
        _deps = deps;
        _variant = variant;
        Parse();
    }

    private void Parse()
    {
        if (_variant == Variant.Map)
        {
            ParseMap();
            return;
        }

        var reader = new PacketReader(_raw);
        _numTimesOpened = reader.ReadU32();
        reader.ReadBytes(4); // padding
        _text = reader.ReadCString();
    }

    private void ParseMap()
    {
        var nul = _raw.Length > MapHeaderBytes ? Array.IndexOf(_raw, (byte)0, MapHeaderBytes) : -1;
        if (nul < 0)
            throw new PacketLayoutException(
                $"Story so far (map) packet is {_raw.Length} bytes; no text string after the {MapHeaderBytes}-byte header",
                MapHeaderBytes);

        if (!PacketText.TryDecode(_raw.AsSpan(MapHeaderBytes, nul - MapHeaderBytes), out _text, allowLineBreaks: true))
            throw new PacketLayoutException("Story so far (map) text does not hold text", MapHeaderBytes);

        _mapHeader = _raw[..MapHeaderBytes];
        _mapRemainder = _raw[(nul + 1)..];
    }

    public void Build()
    {
        // Same gate as QuestPacket's description: if the text isn't japanese
        // (already translated this session, or a non-jp client locale), leave
        // the packet alone.
        if (string.IsNullOrEmpty(_text) || !Translator.IsTextJapanese(_text)) return;

        var translated = TranslateText(_text);
        if (translated == null || translated == _text) return;

        var clipped = TrimToByteLength(translated, MaxTextBytes);
        var byteLen = Encoding.UTF8.GetByteCount(clipped);

        if (_variant == Variant.Map)
        {
            // Plain cstring, no padding: the original has none either.
            var mapWriter = new PacketWriter();
            mapWriter.WriteBytes(_mapHeader);
            mapWriter.WriteCString(clipped);
            mapWriter.WriteBytes(_mapRemainder);
            ModifiedData = mapWriter.Build();
            return;
        }

        var writer = new PacketWriter();
        writer.WriteU32(_numTimesOpened);
        writer.WriteBytes(new byte[4]);
        writer.WriteCString(clipped);

        var pad = FixedTextBlockBytes - byteLen;
        if (pad > 0) writer.WriteBytes(new byte[pad]);

        ModifiedData = writer.Build();
    }

    // bad_strings -> story_so_far db -> machine translation, the same order as
    // QuestPacket's description. The hand-curated rows still win: bad_strings
    // and the story_so_far table (the placeholder-substituted story_so_far_
    // template rows) are checked first, and the backend translator only runs
    // on a miss, with the story-so-far wrap settings (43 wide, 8 lines, no
    // <br> injection -- the in-game recap window is 43 characters per line
    // and 8 lines). A machine translation is written back to story_so_far so
    // the same text is only translated once. (That table is rebuilt from the
    // template whenever the player data is re-materialized, which also drops
    // these cached translations; they are simply translated again on next
    // use.) Returns null on a miss with no translation, leaving the japanese.
    private string? TranslateText(string original)
    {
        var bad = _deps.Db.SearchBadStrings(original);
        if (bad != null) return bad;

        var cached = _deps.Db.Read(original, "story_so_far");
        if (cached != null) return cached;

        var translated = _deps.Translator.Translate(original, wrapWidth: WrapWidth, maxLines: MaxLines, addBrs: false);
        if (string.IsNullOrEmpty(translated)) return null;

        _deps.Db.Write(original, translated, "story_so_far");
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
