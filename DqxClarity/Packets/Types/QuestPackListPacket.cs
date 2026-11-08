using System.Buffers.Binary;
using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The list of purchasable Quest Packs -- opcode 0x5D, marker 0x2562. Each
// entry is a quest sold as a pack (a hometown-stationery unlock, a medal
// exchange, a bath-house quest line...), shown with its chapter name, its
// quest name and its rewards. Unlike QuestPacket, which carries ONE quest with
// its full description, this carries many quests (up to 12 in the captures)
// and NO description -- only chapter, name and rewards, in that order.
//
// The translation rules are QuestPacket's, minus the description:
//   chapter / quest name : m00 'quests' lookup only, left alone on a miss
//   rewards              : QuestRewardFormatter (custom_quest_rewards + items +
//                          key_items), same as QuestPacket's reward fields
// There is no "is the description Japanese" gate because there is no
// description; each field simply translates if its lookup hits.
//
// Layout (offsets are into Data, i.e. after opcode + marker), confirmed
// against three captures of 6, 12 and 9 quests:
//   header      37 bytes -- passthrough. Starts with a u32 that differs per
//               capture (0, 2, 3 -- probably a page/request counter); also
//               holds a timestamp-looking u32 at [16] (identical in all three)
//               and a few small ids. None of it is read.
//   count       u32 at [37] -- number of records in the first list (5, 12, 9)
//   record[]    `count` records, back to back, 237 bytes each:
//                 info        5 x u32 (20 bytes) -- passthrough. In order: an
//                             id, a related id (id + 206 for most records in
//                             the 12-quest capture), a number that looks like
//                             a price, a small number, and a fifth value that
//                             is 150 or 0. Meanings unconfirmed.
//                 chapter     56-byte fixed cstring (empty for most records)
//                 name        56-byte fixed cstring
//                 rewards     104-byte fixed cstring -- up to two reward lines
//                             separated by '\n', like QuestPacket's reward
//                             fields: "・<item>　　...１こ\n・<item>..."
//                 flag        1 byte -- passthrough (0 or 1; it is 1 exactly
//                             on the records whose fifth info value is 0, so
//                             it may mean "already purchased")
//   count2      u32 -- number of records in a second list. 0 in the 12- and
//               9-quest captures; 1 in the 6-quest capture, whose one second-
//               list record is shaped exactly like the others (chapter, name
//               and reward in the same slots).
//   record[]    `count2` records, same 237-byte shape
//   tail        14 bytes -- three u32s and two bytes; passthrough
//
// The totals check out exactly in all three captures: 37 + 4 + 237 x count +
// 4 + 237 x count2 + 14 == Data length (1481, 2903, 2192 bytes).
//
// Everything here is fixed-width, so a translation never changes the packet's
// length or moves anything after it: each translated field is written back
// into its own slot, zero-padded to the slot width and cut (on a utf-8
// character boundary) to leave room for the terminator. Fields whose lookup
// misses are not touched at all. If the counts or lengths ever fail to line up
// with the layout above, Build() leaves the whole packet untouched rather than
// translate on a guess.
//
// NOT crash-tested against a live client yet.
//
// Samples: docs/packets/references/quest_pack_list_1 (6 quests, one in the
//          second list, quest rewards with quantities),
//          docs/packets/references/quest_pack_list_2 (12 quests, stationery
//          unlocks),
//          docs/packets/references/quest_pack_list_3 (9 quests, stationery
//          unlocks)
public sealed class QuestPackListPacket : IPacket
{
    private const int CountOffset = 37;
    private const int InfoBytes = 20;
    private const int ChapterBytes = 56;
    private const int NameBytes = 56;
    private const int RewardBytes = 104;
    private const int FlagBytes = 1;
    private const int RecordBytes = InfoBytes + ChapterBytes + NameBytes + RewardBytes + FlagBytes; // 237
    private const int MaxRecords = 64; // sanity bound; captures show 5-12

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public QuestPackListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < CountOffset + 4) return;

        var data = (byte[])_raw.Clone();
        var changed = false;
        var pos = CountOffset;

        // Two back-to-back lists, each introduced by its own u32 count.
        for (var list = 0; list < 2; list++)
        {
            if (pos + 4 > data.Length) return;
            var count = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(pos, 4));
            pos += 4;

            if (count > MaxRecords) return;
            if ((long)pos + (long)count * RecordBytes > data.Length) return;

            for (var i = 0; i < count; i++)
            {
                if (TranslateRecord(data, pos)) changed = true;
                pos += RecordBytes;
            }
        }

        // Anything left over is the tail (14 bytes in every capture) and is
        // never touched. Only publish the rewritten copy if something changed.
        if (changed) ModifiedData = data;
    }

    // Translates one record in place. `start` is the offset of the record's
    // 20-byte info block. Returns true if any field was rewritten.
    private bool TranslateRecord(byte[] data, int start)
    {
        var chapterAt = start + InfoBytes;
        var nameAt = chapterAt + ChapterBytes;
        var rewardAt = nameAt + NameBytes;

        var changed = false;
        changed |= TryWrite(data, chapterAt, ChapterBytes, LookupQuestName);
        changed |= TryWrite(data, nameAt, NameBytes, LookupQuestName);
        changed |= TryWrite(data, rewardAt, RewardBytes, FormatRewards);
        return changed;
    }

    private static bool TryWrite(byte[] data, int at, int slot, Func<string, string?> translate)
    {
        var term = Array.IndexOf(data, (byte)0, at, slot);
        var len = term < 0 ? slot : term - at;
        if (len == 0) return false;

        var original = Encoding.UTF8.GetString(data, at, len);
        var translated = translate(original);
        if (translated == null || translated == original) return false;

        var bytes = Encoding.UTF8.GetBytes(translated);
        bytes = TruncateUtf8(bytes, slot - 1);

        Array.Clear(data, at, slot);
        Buffer.BlockCopy(bytes, 0, data, at, bytes.Length);
        return true;
    }

    // M00 `quests` lookup with NO fallback: english on a hit, null on a miss.
    // Same as QuestPacket's chapter / quest name handling.
    private string? LookupQuestName(string original)
    {
        var dict = _deps.M00Dict("quests");
        return dict.TryGetValue(original, out var en) && !string.IsNullOrEmpty(en) ? en : null;
    }

    // Reward lines: item lookup + quantity rules, same as QuestPacket.
    private string? FormatRewards(string original)
    {
        var dict = _deps.M00Dict("custom_quest_rewards", "items", "key_items");
        var formatted = new QuestRewardFormatter(dict).Format(original);
        return formatted == original ? null : formatted;
    }

    // Cuts to at most `max` bytes without splitting a utf-8 sequence.
    private static byte[] TruncateUtf8(byte[] bytes, int max)
    {
        if (bytes.Length <= max) return bytes;
        var cut = max;
        while (cut > 0 && (bytes[cut] & 0xC0) == 0x80) cut--;
        return bytes[..cut];
    }
}
