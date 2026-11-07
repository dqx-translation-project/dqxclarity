using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// Names a single quest on one of your Stamp Cards -- opcode 0x5d, marker
// 0xba21. One of these appears to accompany each stamp-card quest slot;
// two distinct samples arrived ~2 seconds apart with different names
// (シオンの花言葉, 第四の詩歌), presumably two different slots on the same
// card -- Data offset 0x08 (u32 = 0x33/51) matches between both captures,
// likely a shared stamp-card id, while Data offset 0x00 (30 vs 39) and a
// 2-byte field at offset 0x1c (0x010c vs 0x004e) both differ and are
// probably quest id/index fields of some kind. None of this is confirmed,
// and none of it needs to be understood to translate the name safely --
// it's all passed through untouched either way.
//
// FIXED-OFFSET "roster" family, same diagnostic used for
// AllianceMemberDetailPacket/TavernRecruitmentListPacket/etc: both sample
// captures are EXACTLY 87 bytes of Data despite the two names having very
// different byte lengths (21 vs 15 bytes) -- conclusive proof this packet
// has a fixed total length that must never change, so a translated name
// needs the fixed-width-slot fix (truncate/zero-pad to the ORIGINAL name's
// byte width), not the free-growth treatment MasterQuestPacket/
// TeamQuestPacket use for their trailing/sequential cstring fields.
//
// Same approach + fix as AllianceMemberDetailPacket (after the あ～にゃ bug
// found there): read the name as ONE atomic null-terminated cstring at its
// confirmed fixed offset (Data offset 0x1e/30 in both captures) rather
// than scanning for Japanese-codepoint runs -- quest names are curated
// game text, not player input, so they can and do contain kanji and
// arbitrary punctuation, and splitting a name into multiple runs based on
// codepoint ranges risks planting a stray NUL mid-name exactly like that
// bug did. The original terminator's position is never moved -- it's
// always re-written explicitly -- so everything after it (a long run of
// zero bytes, then a final 0x01 byte in both samples, meaning unconfirmed)
// is passed through byte-for-byte untouched regardless of translation.
//
// Per the user: quest names are looked up ONLY in m00 'quests' (not
// 'custom_master_quests' or any other quest-name dict) with NO romanizer
// fallback -- a miss passes through as the original Japanese untouched.
//
// Samples: docs/packets/references/stamp_card_quest_1 (シオンの花言葉),
//          docs/packets/references/stamp_card_quest_2 (第四の詩歌)
public sealed class StampCardQuestPacket : IPacket
{
    private const int NameFieldOffset = 0x1E;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public StampCardQuestPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < NameFieldOffset) return;

        var reader = new PacketReader(_raw);
        var header = reader.ReadBytes(NameFieldOffset).ToArray();
        var name = reader.ReadCString();
        // Zero padding out to the fixed record size, plus the trailing
        // flag byte. Passed through byte-for-byte untouched.
        var rest = reader.RemainingBytes().ToArray();

        // Already translated -- hook re-intercepted its own modified write.
        if (!Translator.IsTextJapanese(name)) return;

        var dict = _deps.M00Dict("quests");
        if (!dict.TryGetValue(name, out var resolved) || string.IsNullOrEmpty(resolved) || resolved == name) return;

        var newBytes = Encoding.UTF8.GetBytes(resolved);

        // Fixed-width slot: the ORIGINAL name's total byte length (see the
        // class doc comment -- this packet's total length never varies
        // across samples). Truncate if the translation is longer; zero-pad
        // if shorter. The original terminator is re-written explicitly at
        // its original position, so this can never change the packet's
        // total length.
        var originalNameBytes = Encoding.UTF8.GetByteCount(name);
        if (newBytes.Length > originalNameBytes) newBytes = newBytes[..originalNameBytes];

        var writer = new PacketWriter();
        writer.WriteBytes(header);
        writer.WriteBytes(newBytes);
        writer.WriteBytes(new byte[originalNameBytes - newBytes.Length]); // zero-pad up to the terminator's original position
        writer.WriteU8(0); // the original terminator, unmoved
        writer.WriteBytes(rest);
        ModifiedData = writer.Build();
    }
}
