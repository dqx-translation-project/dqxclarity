using System.Text;

namespace DqxClarity.Packets;

// Thrown when a packet's bytes don't have the shape its class expects -- a
// length field that doesn't fit, a string that isn't text, a count that makes
// no sense. A game update that moves fields around shows up as one of these
// instead of as silently-wrong output.
//
// It is caught by PacketGuard, which (1) leaves the packet completely
// untouched, so the original bytes reach the game and nothing is rewritten at
// a wrong offset, and (2) asks MismatchReporter to save a report with the raw
// bytes, so the layout can be worked out and the class updated.
public sealed class PacketLayoutException : Exception
{
    // Data offset the problem was noticed at, when there is one.
    public int? Offset { get; }

    public PacketLayoutException(string message, int? offset = null) : base(message)
    {
        Offset = offset;
    }
}

// Shared "is this really text?" checks used by the strict PacketReader methods
// and by packets that rewrite fixed-size name slots.
public static class PacketText
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    // Decodes bytes as utf-8 text. False for invalid utf-8 or control
    // characters. The \x04 prefix that translated names carry is allowed, and
    // line breaks / tabs are allowed when allowLineBreaks is set (dialogue).
    public static bool TryDecode(ReadOnlySpan<byte> bytes, out string text, bool allowLineBreaks = false)
    {
        text = "";

        string decoded;
        try { decoded = StrictUtf8.GetString(bytes); }
        catch (DecoderFallbackException) { return false; }

        foreach (var c in decoded)
        {
            if (c >= ' ' || c == '\x04') continue;
            if (allowLineBreaks && (c == '\n' || c == '\r' || c == '\t')) continue;
            return false;
        }

        text = decoded;
        return true;
    }

    // Reads the null-terminated string out of a fixed-size slot (the whole
    // slot when it has no null). An empty slot is fine and gives "". False
    // when what is in the slot isn't text -- typically a sign the slot isn't
    // where the packet class thinks it is.
    public static bool TryReadSlot(ReadOnlySpan<byte> slot, out string text)
    {
        var nul = slot.IndexOf((byte)0);
        return TryDecode(nul < 0 ? slot : slot[..nul], out text);
    }

    // Kana, kanji or half-width kana anywhere in the string.
    public static bool HasJapanese(string s)
    {
        foreach (var c in s)
        {
            if ((c >= '぀' && c <= 'ヿ') ||
                (c >= '一' && c <= '鿿') ||
                (c >= 'ｦ' && c <= 'ﾟ'))
                return true;
        }
        return false;
    }
}
