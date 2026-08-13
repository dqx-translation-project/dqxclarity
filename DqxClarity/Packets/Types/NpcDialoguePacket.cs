using System.IO.Hashing;
using System.Text;
using DqxClarity.Data;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// Wire layout (after opcode + marker have been stripped by DataPacketRouter):
//   num_times_opened     u32
//   padding              4 bytes
//   unknown_1            u16
//   unknown_2            u16
//   text_length          u32  (includes the null terminator)
//   text                 cstring (utf-8, null-terminated)
//   unknown_3            u32  (looks like npc_name length, unused)
//   npc_name             cstring (utf-8, null-terminated)
//   unknown_4            7 bytes
//   bitwise              u32  (purpose unknown -- NOT a crc mask, see below)
//   crc_value            u32  (zlib.crc32(text utf-8), full, unmasked)
public sealed class NpcDialoguePacket : IPacket
{
    // Two known marker variants share this layout with two small deltas:
    //
    //   variant                     | WithName (0xa83c) | NoName (0x9804)
    //   ────────────────────────────|───────────────────|──────────────────
    //   header bytes before tlen    | 12                | 13 (extra 0 byte)
    //   unknown_4 length            | 7 bytes           | 1 byte
    //
    // crc_value is always the plain, unmasked crc32(text) for both variants.
    // This used to be implemented as `crc32(text) & bitwise`, on the theory
    // that `bitwise` was a crc mask -- every WithName capture on hand had
    // bitwise=0xFFFFFFFF, so masking was indistinguishable from not masking
    // and the theory went untested. It broke on system-generated WithName
    // messages that reuse this same packet shape (e.g. the "I accepted the
    // quest ..." notification shown right after QuestAccept), which carry
    // bitwise=0x15 instead. Captured a same-message Japanese-original /
    // English-modified pair for one of these and the proof is direct: the
    // ORIGINAL packet's crc_value is 0x9E3DE2DB, which is exactly
    // crc32(original japanese text) -- the FULL unmasked value, not
    // crc32(text)&0x15 (that would be 0x11). So `bitwise` was never a crc
    // mask at all; it's some other unrelated field we don't understand yet,
    // and crc_value is unconditionally the full crc32 of the text. The old
    // masking logic silently truncated the crc to a handful of bits for any
    // WithName packet where bitwise wasn't 0xFFFFFFFF, which is what was
    // actually corrupting this notification and crashing the client.
    //
    // Samples: docs/packets/references/npc_dialogue (WithName, ordinary
    //          dialogue, bitwise=0xFFFFFFFF),
    //          docs/packets/NpcDialogue_NoName.txt (NoName),
    //          docs/packets/references/npc_dialogue_quest_notice (WithName,
    //          quest-accepted system notification, bitwise=0x15, rendered
    //          fine under the old buggy masking -- coincidence, not proof),
    //          docs/packets/references/npc_dialogue_quest_notice_crash
    //          (same shape/bitwise, crashed the client -- the masked crc
    //          didn't match what the client independently recomputes),
    //          docs/packets/references/npc_dialogue_quest_notice_original and
    //          npc_dialogue_quest_notice_modified (same message captured both
    //          pre- and post-translation -- crc_value is byte-identical to
    //          crc32(original text) in the pre-translation capture, proving
    //          no masking is applied).
    public enum Variant { WithName, NoName }

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;
    private readonly Variant _variant;

    private uint _numTimesOpened;
    private byte[] _padding = Array.Empty<byte>();
    private ushort _unknown1;
    private ushort _unknown2;
    private byte _extraPad;          // present only in NoName variant
    private uint _textLength;
    private string _text = "";
    private uint _unknown3;
    private string _npcName = "";
    private byte[] _unknown4 = Array.Empty<byte>();
    private uint _bitwise;           // purpose unknown, passed through untouched
    private uint _crcValue;

    public byte[]? ModifiedData { get; private set; }

    public NpcDialoguePacket(byte[] payloadData, PacketDependencies deps, Variant variant)
    {
        _raw = payloadData;
        _deps = deps;
        _variant = variant;
        Parse();
    }

    private void Parse()
    {
        var reader = new PacketReader(_raw);
        _numTimesOpened = reader.ReadU32();
        _padding = reader.ReadBytes(4).ToArray();
        _unknown1 = reader.ReadU16();
        _unknown2 = reader.ReadU16();
        if (_variant == Variant.NoName)
            _extraPad = reader.ReadU8();
        _textLength = reader.ReadU32();
        _text = reader.ReadCString();
        _unknown3 = reader.ReadU32();
        _npcName = reader.ReadCString();
        _unknown4 = reader.ReadBytes(_variant == Variant.NoName ? 1 : 7).ToArray();
        _bitwise = reader.ReadU32();
        _crcValue = reader.ReadU32();
    }

    public void Build()
    {
        // Resolve the speaker tag from m00 npcs (+ custom overrides). Falls
        // back to romaji so the player sees something readable even when the
        // dict misses. We pass the ORIGINAL japanese name to TranslateText so
        // the dialog cache stays keyed on the wire-stable speaker id.
        var newName = ResolveSpeakerName(_npcName);
        var modifiedText = TranslateText(_text, _npcName);

        var nameChanged = newName != _npcName;
        var textChanged = modifiedText != null && modifiedText != _text;
        if (!nameChanged && !textChanged) return;

        var finalText = textChanged ? modifiedText! : _text;
        var finalName = nameChanged ? newName : _npcName;

        var writer = new PacketWriter();
        writer.WriteU32(_numTimesOpened);
        writer.WriteBytes(_padding);
        writer.WriteU16(_unknown1);
        writer.WriteU16(_unknown2);
        if (_variant == Variant.NoName)
            writer.WriteU8(_extraPad);
        // text + name lengths include the null terminator (utf-8 bytes + 1)
        writer.WriteU32((uint)(Encoding.UTF8.GetByteCount(finalText) + 1));
        writer.WriteCString(finalText);
        writer.WriteU32((uint)(Encoding.UTF8.GetByteCount(finalName) + 1));
        writer.WriteCString(finalName);
        writer.WriteBytes(_unknown4);
        writer.WriteU32(_bitwise);
        writer.WriteU32(CalculateCrc(finalText));
        ModifiedData = writer.Build();
    }

    // M00 "npcs" lookup with custom_npc_name_overrides layered on top
    // (same source EntityPacket uses for its Npc subtype). Romaji fallback
    // when the dict misses — same pattern as EntityPacket's Player branch.
    private string ResolveSpeakerName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese)) return japanese;
        var dict = _deps.NpcNameDict();
        if (dict.TryGetValue(japanese, out var en) && !string.IsNullOrEmpty(en))
            return en;
        return _deps.Romanizer.ToRomaji(japanese);
    }

    // crc_value is always the full, unmasked crc32(text) -- see the class
    // doc comment for the direct proof that `bitwise` isn't a mask on this.
    private static uint CalculateCrc(string text)
    {
        var crc = new Crc32();
        crc.Append(Encoding.UTF8.GetBytes(text));
        return BitConverter.ToUInt32(crc.GetHashAndReset());
    }

    private string? TranslateText(string original, string npcName)
    {
        // Bad-strings table catches known-bad translations and returns the curated en.
        var bad = _deps.Db.SearchBadStrings(original);
        if (bad != null) return bad;

        // Cache hit.
        var cached = _deps.Db.Read(original, "dialog");
        if (cached != null) return cached;

        // Machine-translate, then cache the result.
        var translated = _deps.Translator.Translate(original, wrapWidth: 46);
        if (string.IsNullOrEmpty(translated)) return original;

        _deps.Db.WriteDialog(original, translated, npcName);
        return translated;
    }
}
