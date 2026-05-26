using DqxClarity.Translation;
using System.Text;

namespace DqxClarity.Packets.Types;

// Two packet variants share this class:
//
//   Variant.Log    (0x5d 0xcc51) — quest log screen (viewing an existing quest)
//   Variant.Accept (0x5d 0x2b15) — accepting a new quest from an NPC
//
// Both variants have identical fields and translation logic. The only structural
// difference is that Log includes an extra `unknown_1` u16 field in the header
// that Accept omits, shifting every subsequent field offset by 2 bytes.
//
// Layout (after opcode + marker):
//   num_times_opened     u32
//   padding              4 bytes
//   unknown_1            u16   ← Log variant only; absent in Accept
//   quest_number         u32
//   unknown_2            u32
//   unknown_3            u32
//   unknown_4            u32
//   unknown_5            u32   ← absence caused 4-byte offset shift corrupting
//                               chapter/name lookups and description writes
//   subquest_name        56-byte fixed cstring   (called "chapter" historically)
//   quest_name           56-byte fixed cstring
//   quest_description    508-byte fixed cstring
//   quest_rewards        104-byte fixed cstring  (one-shot rewards)
//   quest_repeat_rewards 104-byte fixed cstring  (repeat-completion rewards)
//   remainder            (passthrough)
//
// Translation strategy — do not machine-translate any of these fields blindly:
//
//   subquest_name / quest_name        : M00 `quests` lookup only. Null on miss
//                                       so we leave the original japanese in
//                                       place rather than emit garbled MT.
//   quest_description                 : bad_strings -> db cache -> MT against
//                                       the `quests` table, with the quest-
//                                       specific wrap settings (49 wide, 6
//                                       lines, no <br> injection).
//   quest_rewards / repeat_rewards    : QuestRewardFormatter — item lookups against
//                                       custom_quest_rewards + items + key_items,
//                                       qty rules, 31-byte slot padding.
//
// Whole packet is gated on `IsTextJapanese(description)` — if the desc isn't
// japanese (already translated this session, or a non-jp client), we don't
// touch anything else either.
public sealed class QuestPacket : IPacket
{
    public enum Variant { Log, Accept }
    private const int ChapterBytes     = 56;
    private const int NameBytes        = 56;
    private const int DescriptionBytes = 508;
    private const int RewardBytes      = 104;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;
    private readonly Variant _variant;

    private uint _numTimesOpened;
    private byte[] _padding = Array.Empty<byte>();
    private ushort _unknown1; // Log variant only
    private uint _questNumber;
    private uint _unknown2;
    private uint _unknown3;
    private uint _unknown4;
    private uint _unknown5;
    private string _chapter = "";
    private string _name = "";
    private string _description = "";
    private string _reward1 = "";
    private string _reward2 = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public QuestPacket(byte[] payloadData, PacketDependencies deps, Variant variant = Variant.Log)
    {
        _raw = payloadData;
        _deps = deps;
        _variant = variant;
        Parse();
    }

    private static string ReadFixedString(ref PacketReader reader, int byteCount)
    {
        var bytes = reader.ReadBytes(byteCount);
        // strip trailing nulls
        var len = bytes.Length;
        while (len > 0 && bytes[len - 1] == 0) len--;
        return Encoding.UTF8.GetString(bytes[..len]);
    }

    private void Parse()
    {
        var reader = new PacketReader(_raw);
        _numTimesOpened = reader.ReadU32();
        _padding = reader.ReadBytes(4).ToArray();
        if (_variant == Variant.Log) _unknown1 = reader.ReadU16();
        _questNumber = reader.ReadU32();
        _unknown2 = reader.ReadU32();
        _unknown3 = reader.ReadU32();
        _unknown4 = reader.ReadU32();
        _unknown5 = reader.ReadU32();
        _chapter     = ReadFixedString(ref reader, ChapterBytes);
        _name        = ReadFixedString(ref reader, NameBytes);
        _description = ReadFixedString(ref reader, DescriptionBytes);
        _reward1     = ReadFixedString(ref reader, RewardBytes);
        _reward2     = ReadFixedString(ref reader, RewardBytes);
        _remainder   = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        // Gate: if the description isn't japanese (already translated this
        // session, or a non-jp client locale), don't touch any field.
        if (!Translator.IsTextJapanese(_description)) return;

        var newChapter     = LookupQuestName(_chapter);
        var newName        = LookupQuestName(_name);
        var newDescription = TranslateDescription(_description);
        var newReward1     = FormatRewards(_reward1);
        var newReward2     = FormatRewards(_reward2);

        if (newChapter == null && newName == null && newDescription == null
            && newReward1 == null && newReward2 == null) return;

        var writer = new PacketWriter();
        writer.WriteU32(_numTimesOpened);
        writer.WriteBytes(new byte[4]);
        if (_variant == Variant.Log) writer.WriteU16(_unknown1);
        writer.WriteU32(_questNumber);
        writer.WriteU32(_unknown2);
        writer.WriteU32(_unknown3);
        writer.WriteU32(_unknown4);
        writer.WriteU32(_unknown5);

        WritePadded(writer, newChapter     ?? _chapter,     ChapterBytes);
        WritePadded(writer, newName        ?? _name,        NameBytes);
        WritePadded(writer, newDescription ?? _description, DescriptionBytes);
        WritePadded(writer, newReward1     ?? _reward1,     RewardBytes);
        WritePadded(writer, newReward2     ?? _reward2,     RewardBytes);

        writer.WriteBytes(_remainder);
        ModifiedData = writer.Build();
    }

    // M00 `quests` lookup with NO fallback. Returns english name on hit, null on miss.
    private string? LookupQuestName(string original)
    {
        if (string.IsNullOrEmpty(original)) return null;
        var dict = _deps.M00Dict("quests");
        return dict.TryGetValue(original, out var en) && !string.IsNullOrEmpty(en) ? en : null;
    }

    // Description path: bad_strings -> db cache -> MT with quest-specific
    // wrap settings (49 wide, 6 max lines, no <br> injection). Writes to db on MT hit.
    private string? TranslateDescription(string original)
    {
        if (string.IsNullOrEmpty(original)) return null;

        var bad = _deps.Db.SearchBadStrings(original);
        if (bad != null) return bad;

        var cached = _deps.Db.Read(original, "quests");
        if (cached != null) return cached;

        var translated = _deps.Translator.Translate(original, wrapWidth: 49, maxLines: 6, addBrs: false);
        if (string.IsNullOrEmpty(translated)) return null;

        _deps.Db.Write(original, translated, "quests");
        return translated;
    }

    // Reward fields: item lookup + qty rules + slot padding.
    // m00 dict is `custom_quest_rewards` + `items` + `key_items` layered together.
    private string? FormatRewards(string original)
    {
        if (string.IsNullOrEmpty(original)) return null;
        var dict = _deps.M00Dict("custom_quest_rewards", "items", "key_items");
        var formatted = new QuestRewardFormatter(dict).Format(original);
        return formatted == original ? null : formatted;
    }

    // Writes the string + null terminator + zero-padding to a fixed total of `slot` bytes.
    // Trims so utf-8 byte count stays within slot - 1.
    private static void WritePadded(PacketWriter writer, string s, int slot)
    {
        var maxBytes = slot - 1;
        var bytes = Encoding.UTF8.GetBytes(s);
        if (bytes.Length > maxBytes)
        {
            var sb = new StringBuilder();
            var running = 0;
            foreach (var c in s)
            {
                var cb = Encoding.UTF8.GetByteCount(new[] { c });
                if (running + cb > maxBytes) break;
                sb.Append(c);
                running += cb;
            }
            bytes = Encoding.UTF8.GetBytes(sb.ToString());
        }
        writer.WriteBytes(bytes);
        var pad = slot - bytes.Length;
        if (pad > 0) writer.WriteBytes(new byte[pad]);
    }
}
