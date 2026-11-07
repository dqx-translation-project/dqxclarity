using System.Buffers.Binary;
using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The "fellow monster" entry of the Support Party menu. The server sends the
// same monster record twice, in two different packets that arrive in the same
// millisecond:
//
//   0xA1 / 0x3BD0  -- 358-byte payload: a 256-byte header (floats, ids) followed
//                     by the monster record.
//   0xA1 / 0x7E96  -- 110-byte payload: an 8-byte header followed by the
//                     identical monster record.
//
// Which of the two actually feeds the menu text isn't known (they carry the same
// name), so both are routed to this class and both get translated.
//
// Monster record (99 bytes): a stat block, then
//   [u32 length incl. null][utf-8 name][0x00] [8 zero bytes] [0x01]
// The name is length-prefixed, so -- same reasoning as MonsterTavernListPacket
// and the Player/Party names in EntityPacket -- it can be resized as long as the
// length is rewritten. That is an inference from the prefix, not crash-tested.
// If a translated name ever corrupts the client, this record is actually a
// fixed-slot field and needs truncate/zero-pad treatment instead.
//
// Approach: same as MonsterTavernListPacket -- scan for
// [u32 length][Japanese run of exactly length-1 bytes][0x00]. Nothing else in
// the packet is modeled, so a layout change elsewhere in the record won't break it.
//
// Name resolution: local_player_names (player-given nicknames), then monsters
// (species names), then custom_npc_name_overrides, then romaji (11 chars max,
// like the other party-style name fields). Already-translated names are ASCII
// and left alone, so the hook re-intercepting its own write can't loop.
//
// Samples: docs/packets/references/support_monster_1 (0x3BD0),
//          docs/packets/references/support_monster_2 (0x7E96)
public sealed class SupportMonsterPacket : IPacket
{
    private const int MinNameLength = 4;
    private const int MaxNameLength = 128;
    private const int MaxRomajiLength = 11;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public SupportMonsterPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        var playerDict = _deps.M00Dict("local_player_names");
        var monsterDict = _deps.M00Dict("monsters");
        var overrideDict = _deps.M00Dict("custom_npc_name_overrides");
        var changed = false;
        var writer = new PacketWriter();

        var i = 0;
        while (i < _raw.Length)
        {
            if (TryReadNameField(_raw, i, out var fieldLen, out var text))
            {
                var newName = Resolve(text, playerDict, monsterDict, overrideDict);
                if (newName != text)
                {
                    changed = true;
                    var newBytes = Encoding.UTF8.GetBytes(newName);
                    writer.WriteU32((uint)(newBytes.Length + 1));
                    writer.WriteBytes(newBytes);
                    writer.WriteU8(0);
                }
                else
                {
                    writer.WriteBytes(_raw.AsSpan(i, 4 + fieldLen).ToArray());
                }

                i += 4 + fieldLen;
            }
            else
            {
                writer.WriteU8(_raw[i]);
                i++;
            }
        }

        if (!changed) return;
        ModifiedData = writer.Build();
    }

    private string Resolve(
        string japanese,
        Dictionary<string, string> playerDict,
        Dictionary<string, string> monsterDict,
        Dictionary<string, string> overrideDict)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        if (playerDict.TryGetValue(japanese, out var p) && !string.IsNullOrEmpty(p)) return p;
        if (monsterDict.TryGetValue(japanese, out var m) && !string.IsNullOrEmpty(m)) return m;
        if (overrideDict.TryGetValue(japanese, out var o) && !string.IsNullOrEmpty(o)) return o;
        return _deps.Romanizer.ToRomaji(japanese, MaxRomajiLength);
    }

    // `fieldLen` on success is the u32 value (name bytes + null), excluding the
    // 4-byte prefix itself.
    private static bool TryReadNameField(byte[] data, int start, out int fieldLen, out string text)
    {
        fieldLen = 0;
        text = "";

        if (start + 4 > data.Length) return false;
        var length = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(start, 4));
        if (length < MinNameLength || length > MaxNameLength) return false;

        var nameStart = start + 4;
        if (nameStart + length > data.Length) return false;

        var strBytes = (int)length - 1;
        if (strBytes <= 0) return false;
        if (data[nameStart + strBytes] != 0) return false;
        if (JapaneseRunLength(data, nameStart) != strBytes) return false;

        text = Encoding.UTF8.GetString(data, nameStart, strBytes);
        fieldLen = (int)length;
        return true;
    }

    private static int JapaneseRunLength(byte[] data, int start)
    {
        var i = start;
        while (i + 3 <= data.Length)
        {
            var b0 = data[i];
            var b1 = data[i + 1];
            var b2 = data[i + 2];
            if ((b0 & 0xF0) != 0xE0) break;
            if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) break;
            var cp = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
            if (!((cp >= 0x3040 && cp <= 0x30FF) || (cp >= 0x4E00 && cp <= 0x9FFF))) break;
            i += 3;
        }
        return i - start;
    }
}
