using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The "Quest Guide" shown under the command window: the name of the quest the
// game is currently guiding you to -- opcode 0x5D, marker 0xF8E1.
//
// Layout (after opcode + marker), from two captures (83 bytes of Data each):
//   header   11 bytes -- 8 bytes (first byte 00 / 01 between captures, the
//            rest zero), a 01, then the quest number as a u16 (DB 00 = 219,
//            1F 01 = 287). The quest number matches the one in the Quest
//            Synopsis packet for the same quest. Passthrough.
//   name     72-byte fixed cstring (utf-8, null-terminated, zero-padded)
//
// Only the quest name is translated: an M00 'quests' lookup, then the Strike
// Force pattern (<monster>討伐！ -> "Hunt <monster>!") the Quest Log uses for
// the same quests. On a miss the packet is left alone -- no machine
// translation. The slot is fixed, so the English is cut to the window's
// 31-character limit (and to the slot) and written in place; the packet never
// changes length.
//
// A packet that is not 83 bytes, or whose name slot is not text, is a layout
// we do not know: it is left untouched and reported (PacketLayoutException).
public sealed class QuestGuidePacket : IPacket
{
    private const int HeaderBytes = 11;
    private const int NameBytes   = 72;
    private const int MaxChars    = 31;   // widest name the guide window shows

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public QuestGuidePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length != HeaderBytes + NameBytes)
            throw new PacketLayoutException(
                $"Quest guide is {_raw.Length} bytes, expected {HeaderBytes + NameBytes}");

        if (!PacketText.TryReadSlot(_raw.AsSpan(HeaderBytes, NameBytes), out var name))
            throw new PacketLayoutException("Quest guide name slot does not hold text", HeaderBytes);

        // Empty, or already english (re-intercepted write / non-jp client).
        if (name.Length == 0 || !Translator.IsTextJapanese(name)) return;

        var english = Lookup(name);
        if (string.IsNullOrEmpty(english)) return;

        if (english.Length > MaxChars) english = english[..MaxChars].TrimEnd();

        var bytes = TruncateUtf8(Encoding.UTF8.GetBytes(english), NameBytes - 1);
        if (bytes.Length == 0) return;

        // Copy the original and rewrite only the name slot.
        var result = (byte[])_raw.Clone();
        Array.Clear(result, HeaderBytes, NameBytes);
        Buffer.BlockCopy(bytes, 0, result, HeaderBytes, bytes.Length);

        ModifiedData = result;
    }

    private string? Lookup(string original)
    {
        var quests = _deps.M00Dict("quests");
        if (quests.TryGetValue(original, out var en) && !string.IsNullOrEmpty(en)) return en;
        return StrikeForceQuestName.Translate(original, _deps.M00Dict("monsters"));
    }

    private static byte[] TruncateUtf8(byte[] bytes, int max)
    {
        if (bytes.Length <= max) return bytes;
        var cut = max;
        // Back up off any UTF-8 continuation byte so a character isn't split.
        while (cut > 0 && (bytes[cut] & 0xC0) == 0x80) cut--;
        return bytes[..cut];
    }
}
