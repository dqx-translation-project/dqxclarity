using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// A quest name sent on its own -- opcode 0x5D, marker 0xA446. It carries the
// same kind of data as the Quest Guide packet (0xF8E1): a quest number and the
// quest's name. What screen shows it is not known yet.
//
// Layout (after opcode + marker), from one capture (66 bytes of Data):
//   header   10 bytes -- 8 zero bytes, then the quest number as a u16
//            (1F 01 = 287, the same quest number the Quest Synopsis packet
//            carries for that quest). Passthrough.
//   name     56-byte fixed cstring (utf-8, null-terminated, zero-padded)
//
// Only the name is translated: an M00 'quests' lookup, then the Strike Force
// pattern (<monster>討伐！ -> "Hunt <monster>!"). On a miss the packet is left
// alone -- no machine translation. The English is written into the same slot
// (cut on a character boundary if it exceeds 55 bytes), so the packet never
// changes length. Unlike the Quest Guide there is no known on-screen width
// limit, so only the slot size applies.
//
// A packet that is not 66 bytes, or whose name slot is not text, is a layout
// we do not know: it is left untouched and reported (PacketLayoutException).
//
// Sample: docs/packets/references/quest_name_1 (ママと私の魔法仕立て術！)
public sealed class QuestNamePacket : IPacket
{
    private const int HeaderBytes = 10;
    private const int NameBytes   = 56;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public QuestNamePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length != HeaderBytes + NameBytes)
            throw new PacketLayoutException(
                $"Quest name packet is {_raw.Length} bytes, expected {HeaderBytes + NameBytes}");

        if (!PacketText.TryReadSlot(_raw.AsSpan(HeaderBytes, NameBytes), out var name))
            throw new PacketLayoutException("Quest name slot does not hold text", HeaderBytes);

        // Empty, or already english (re-intercepted write / non-jp client).
        if (name.Length == 0 || !Translator.IsTextJapanese(name)) return;

        var english = Lookup(name);
        if (string.IsNullOrEmpty(english)) return;

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
