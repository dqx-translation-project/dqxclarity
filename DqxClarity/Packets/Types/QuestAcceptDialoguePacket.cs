using System.Text;

namespace DqxClarity.Packets.Types;

// The dialogue box that prints "Accepted the quest <questname>" right after
// accepting a quest -- opcode 0x21, marker 0x8F8F. Not to be confused with
// QuestPacket's Accept variant (opcode 0x5d, marker 0x2b15), which is the
// quest-log ENTRY itself (name/chapter/description/rewards); this is just
// the transient toast/dialogue line printed at the moment of acceptance.
//
// Per the user: this packet carries several different kinds of dialogue,
// distinguished by a named variable field (var_name below) -- "EV_QUEST_NAME"
// is the one that matters here (the quest-accepted line); other var_name
// values carry other dialogue this class deliberately leaves untouched.
//
// Layout (after opcode + marker), confirmed identical in shape across both
// captures on hand:
//   unknown_1        u32 -- differs between captures (16 vs 19), maybe a
//                    dialogue/window/event index. Passthrough, unconfirmed.
//   zero             u32 -- 0 in both captures. Passthrough.
//   var_name_length  u32 -- utf-8 byte length of var_name INCLUDING the null
//                    terminator. Load-bearing (recomputed on write): matched
//                    "EV_QUEST_NAME\0"'s exact 14-byte length in both
//                    captures.
//   var_name         cstring (ascii, null-terminated) -- "EV_QUEST_NAME" in
//                    both captures on hand. This class only acts when
//                    var_name is EXACTLY "EV_QUEST_NAME"; any other value is
//                    passed through completely untouched, since the user
//                    only wants this variable type translated for now.
//   quest_name_length u32 -- utf-8 byte length of quest_name INCLUDING the
//                    null terminator. Load-bearing (recomputed on write):
//                    matched quest_name's exact byte length in both captures
//                    (31 for "ヴァルハラの戦士たち", 28 for
//                    "求めるは仙者の霊薬").
//   quest_name       cstring (utf-8, null-terminated) -- the quest's
//                    Japanese title. The LAST field in both captures (nothing
//                    follows it), so this is free to grow/shrink on
//                    translation the same way SugorokuItemNotificationPacket/
//                    NpcDialoguePacket's length-prefixed-and-last fields are,
//                    not a fixed-width-slot case.
//
// quest_name looked up in m00 'quests' with NO romaji fallback -- a miss
// passes through as the original Japanese untouched, per the user and
// matching QuestPacket's own LookupQuestName policy for this same curated,
// fixed dictionary (not freeform prose, so an unrecognized title shouldn't
// get transliterated into meaningless kana-to-latin noise).
//
// Samples: docs/packets/references/quest_accept_dialogue_valhalla,
//          docs/packets/references/quest_accept_dialogue_elixir (confirms
//          the header/length-field layout across two different quest names)
public sealed class QuestAcceptDialoguePacket : IPacket
{
    private const string TargetVarName = "EV_QUEST_NAME";

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private bool _recognized;
    private uint _unknown1;
    private uint _zero;
    private string _varName = "";
    private string _questName = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public QuestAcceptDialoguePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < 12) return;
        var reader = new PacketReader(_raw);
        _unknown1 = reader.ReadU32();
        _zero = reader.ReadU32();

        if (reader.Remaining < 4) return;
        _ = reader.ReadU32(); // var_name_length -- recomputed on write
        _varName = reader.ReadCString();

        // Other variable types ride on this same packet shape -- only
        // EV_QUEST_NAME is handled here, per the user. Bail out (no
        // ModifiedData) for anything else so it passes through untouched.
        if (_varName != TargetVarName) return;

        if (reader.Remaining < 4) return;
        _ = reader.ReadU32(); // quest_name_length -- recomputed on write
        _questName = reader.ReadCString();
        _remainder = reader.RemainingBytes().ToArray();

        _recognized = true;
    }

    public void Build()
    {
        if (!_recognized) return;

        var dict = _deps.M00Dict("quests");
        if (!dict.TryGetValue(_questName, out var newName) || string.IsNullOrEmpty(newName)) return;
        if (newName == _questName) return;

        var writer = new PacketWriter();
        writer.WriteU32(_unknown1);
        writer.WriteU32(_zero);

        var varNameBytes = Encoding.UTF8.GetBytes(_varName);
        writer.WriteU32((uint)(varNameBytes.Length + 1)); // include null terminator in length
        writer.WriteCString(_varName);

        var questNameBytes = Encoding.UTF8.GetBytes(newName);
        writer.WriteU32((uint)(questNameBytes.Length + 1)); // include null terminator in length
        writer.WriteCString(newName);

        writer.WriteBytes(_remainder);
        ModifiedData = writer.Build();
    }
}
