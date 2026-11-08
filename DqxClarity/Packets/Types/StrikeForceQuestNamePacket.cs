using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The name of a Strike Force quest, sent on its own -- opcode 0x5D, marker
// 0x374A. Strike Force quest names come from the server rather than the
// client's local files, so there are no dictionary entries for them; they
// always follow <japanese monster name>討伐！, translated as
// "Hunt <english monster name>!" by looking the monster up in the m00
// 'monsters' dictionary. See StrikeForceQuestName for the pattern, which
// QuestPacket also uses for the same quests' names in the Quest Log and Quest
// Accept packets.
//
// Layout (after opcode + marker), from two captures (72 bytes of Data each):
//   header   14 bytes -- 8 zero bytes, u32 01 00 00 00, then a 2-byte id
//            (59 4A in one capture, C5 43 in the other). The id is the
//            quest's number: it is the same value the Quest Accept packet
//            carries as its quest_number for that quest (C5 43 in the
//            こうていタップ capture). Passthrough.
//   name     56-byte fixed cstring (utf-8, null-terminated, zero-padded) --
//            the same slot size as QuestPacket's chapter/name fields
//   tail     2 bytes -- 01 00 in both captures. Passthrough.
//
// The name is written back into the same 56-byte slot (zero-padded, cut on a
// utf-8 character boundary if it ever exceeded 55 bytes), so the packet's
// length never changes. A name that doesn't match the pattern, or whose
// monster isn't in the dictionary, leaves the packet untouched.
//
// Samples: docs/packets/references/strike_force_quest_name_1
//          (暴君バサグランデ強討伐！) and strike_force_quest_name_2
//          (こうていタップ討伐！)
public sealed class StrikeForceQuestNamePacket : IPacket
{
    private const int HeaderBytes = 14;
    private const int NameBytes   = 56;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private string _name = "";
    private bool _parsed;

    public byte[]? ModifiedData { get; private set; }

    public StrikeForceQuestNamePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes + NameBytes) return;

        var len = NameBytes;
        // Cstring inside the fixed slot: stop at the first null.
        var nul = Array.IndexOf(_raw, (byte)0, HeaderBytes, NameBytes);
        if (nul >= 0) len = nul - HeaderBytes;

        _name = Encoding.UTF8.GetString(_raw, HeaderBytes, len);
        _parsed = true;
    }

    public void Build()
    {
        if (!_parsed || _name.Length == 0) return;

        var translated = StrikeForceQuestName.Translate(_name, _deps.M00Dict("monsters"));
        if (translated == null || translated == _name) return;

        var bytes = TruncateUtf8(Encoding.UTF8.GetBytes(translated), NameBytes - 1);

        // Copy the original and rewrite only the name slot.
        var result = (byte[])_raw.Clone();
        Array.Clear(result, HeaderBytes, NameBytes);
        Buffer.BlockCopy(bytes, 0, result, HeaderBytes, bytes.Length);

        ModifiedData = result;
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
