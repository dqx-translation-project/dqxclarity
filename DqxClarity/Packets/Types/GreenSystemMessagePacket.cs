using System.Text;
using System.Text.RegularExpressions;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The green system message logged in the chat window when you pick up an
// item -- opcode 0x1F, marker 0x8C41. The server builds the japanese text from
// fixed templates, so rather than machine translating it, the line is matched
// and rebuilt in english from dictionary lookups. Order of attempts:
//
//   1. Fixed lines: exact whole-line entries in m00 'custom_corner_text'
//      (SystemLineTranslator.FixedLine).
//   2. The pick-up form below, which is specific to this packet.
//   3. Every other template -- defeat/collect/acquire lines, a player
//      collecting or using an item, chests transforming, running out of an
//      item -- shared with QuestProgressPacket in SystemLineTranslator (see
//      that class for the full list). That includes "<item>を 手に入れた！" with
//      no amount, which gives "Received <item>!".
//
// The pick-up form handled here:
//
//   With an amount
//     ja: <item>を <number>個 手に入れた！
//         せかいじゅの葉を 5個 手に入れた！
//     ja: <item>を <number>枚 手に入れた！
//         ちいさいメダルを 5枚 手に入れた！
//     en: Received <number> <item>!
//     (個 and 枚 are just different counters -- items vs. flat things like
//     medals -- and both give the same english form)
//
// The item name is looked up in m00 'items', then 'key_items'. Matching is on
// the whole line (tolerant of the spacing between parts) and whole-or-nothing:
// if the line isn't one of these forms, or the item isn't in either
// dictionary, the packet is left untouched and the japanese shows -- no
// machine translation, no romaji. The number may be full-width and is written
// back as plain digits.
//
// Layout (after opcode + marker), from two captures (66 and 52 bytes of Data):
//   header       12 bytes -- 8 zero bytes, then u32 0x13 (19) in both
//                captures (looks like a message kind / color id). Passthrough.
//   text_length  u32 -- utf-8 byte length of the text INCLUDING the null
//                terminator (confirmed exact: 0x31 = 49 and 0x23 = 35).
//                Load-bearing, recomputed on write.
//   text         cstring (utf-8, null-terminated)
//   tail         1 byte -- 01 in both captures. Passthrough.
//
// The text is variable-length, so the english is written in place of the
// japanese and text_length recomputed -- the same shape as CornerTextPacket
// and QuestProgressPacket.
//
// Samples: docs/packets/references/green_system_message_1
//          (せかいじゅの葉を 5個 手に入れた！) and green_system_message_2
//          (ビンゴ券を 手に入れた！)
public sealed class GreenSystemMessagePacket : IPacket
{
    private const int HeaderBytes = 12;
    private const int LengthFieldBytes = 4;

    private const string Num = @"[0-9０-９]+";

    private static readonly Regex WithAmountRe = new(
        @"^(?<item>.+?)を\s*(?<amount>" + Num + @")(?:個|枚)\s*手に入れた！$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;
    private readonly SystemLineTranslator _lines;

    private byte[] _header = Array.Empty<byte>();
    private string _text = "";
    private byte[] _tail = Array.Empty<byte>();
    private bool _parsed;

    public byte[]? ModifiedData { get; private set; }

    public GreenSystemMessagePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
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

        var english = Translate(_text);
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

    // Returns the english line, or null when nothing matches or a name can't
    // be resolved. Fixed lines win, then this packet's own pick-up form, then
    // the shared templates. If the pick-up form matches but its item isn't
    // known, the shared templates still get a turn (a "<player>は <item>を
    // <n>個 手に入れた！" line has the same ending but a player in front).
    private string? Translate(string text) =>
        _lines.FixedLine(text) ?? TranslatePickUp(text) ?? _lines.Templates(text);

    private string? TranslatePickUp(string text)
    {
        var m = WithAmountRe.Match(text);
        if (!m.Success) return null;

        var item = LookupItem(m.Groups["item"].Value);
        return item == null ? null : $"Received {Digits(m.Groups["amount"].Value)} {item}!";
    }

    // items first, then key_items (key_items only consulted on an items miss).
    private string? LookupItem(string ja) =>
        Lookup(_deps.M00Dict("items"), ja) ?? Lookup(_deps.M00Dict("key_items"), ja);

    private static string? Lookup(Dictionary<string, string> dict, string ja) =>
        dict.TryGetValue(ja, out var en) && !string.IsNullOrEmpty(en) ? en : null;

    // Number as plain ascii digits (handles full-width).
    private static string Digits(string s)
    {
        var d = s.Normalize(NormalizationForm.FormKC).Trim().TrimStart('0');
        return d.Length > 0 ? d : "0";
    }
}
