using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The quest-progress line shown at the bottom of the screen while you work on
// a quest -- opcode 0x21, marker 0x1305. The server builds the japanese text
// from fixed templates; the translation itself (fixed lines from
// custom_corner_text first, then each template rebuilt in english from
// dictionary lookups) lives in SystemLineTranslator, which this packet shares
// with GreenSystemMessagePacket. See that class for the list of templates and
// how names are resolved. A line that matches nothing is left untouched.
//
// Layout (after opcode + marker), from three captures (72, 73 and 87 bytes of
// Data):
//   header       8 bytes -- u32 (04 / 05 / 00 in the captures; meaning
//                unknown, maybe a kind or counter) + u32 0. Passthrough.
//   text_length  u32 -- utf-8 byte length of the text INCLUDING the null
//                terminator (confirmed exact in all three: 0x34, 0x35, 0x43).
//                Load-bearing, recomputed on write.
//   text         cstring (utf-8, null-terminated)
//   tail         8 bytes -- 05 00 00 00 00 00 00 00 in all three. Passthrough.
//
// The text is variable-length (the packet is already a different size every
// time the line changes), so the english is written in place of the japanese
// and text_length recomputed -- the same shape as CornerTextPacket.
//
// Samples: docs/packets/references/quest_progress_monster_1 / _2
//          (こうていタップ, 9匹目 and 11匹目) and quest_progress_skill
//          (ドルマ + バアラック)
public sealed class QuestProgressPacket : IPacket
{
    private const int HeaderBytes = 8;
    private const int LengthFieldBytes = 4;

    private readonly byte[] _raw;
    private readonly SystemLineTranslator _lines;

    private byte[] _header = Array.Empty<byte>();
    private string _text = "";
    private byte[] _tail = Array.Empty<byte>();
    private bool _parsed;

    public byte[]? ModifiedData { get; private set; }

    public QuestProgressPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _lines = new SystemLineTranslator(deps);
        Parse();
    }

    private void Parse()
    {
        var textStart = HeaderBytes + LengthFieldBytes;
        if (_raw.Length < textStart + 1) return;

        var terminator = Array.IndexOf(_raw, (byte)0, textStart);
        if (terminator < 0) return;

        _header = _raw[..HeaderBytes];
        _text   = Encoding.UTF8.GetString(_raw, textStart, terminator - textStart);
        _tail   = _raw[(terminator + 1)..];
        _parsed = true;
    }

    public void Build()
    {
        if (!_parsed || _text.Length == 0) return;
        // Already english (re-intercepted modified write, or a non-jp client).
        if (!Translator.IsTextJapanese(_text)) return;

        var english = _lines.Translate(_text);
        if (english == null || english == _text) return;

        var textBytes = Encoding.UTF8.GetBytes(english);

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteU32((uint)(textBytes.Length + 1)); // includes the null terminator
        writer.WriteBytes(textBytes);
        writer.WriteBytes(new byte[1]);
        writer.WriteBytes(_tail);

        ModifiedData = writer.Build();
    }
}
