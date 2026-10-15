using System.Text;
using DqxClarity.Translation;

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
        // Same gate as QuestPacket's description: if the text isn't japanese
        // (already translated this session, or a non-jp client locale), leave
        // the packet alone.
        if (string.IsNullOrEmpty(_text) || !Translator.IsTextJapanese(_text)) return;

        var translated = TranslateText(_text);
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
