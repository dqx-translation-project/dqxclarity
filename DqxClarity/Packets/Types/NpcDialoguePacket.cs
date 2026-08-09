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
//   bitwise              u32  (masks the crc)
//   crc_value            u32  (zlib.crc32(text utf-8) & bitwise)
public sealed class NpcDialoguePacket : IPacket
{
    // Two known marker variants share this layout with three small deltas:
    //
    //   variant                     | WithName (0xa83c) | NoName (0x9804)
    //   ────────────────────────────|───────────────────|──────────────────
    //   header bytes before tlen    | 12                | 13 (extra 0 byte)
    //   unknown_4 length            | 7 bytes           | 1 byte
    //   stored crc strategy         | crc32(text) & bw  | crc32(text) (full)
    //
    // In WithName captures the `bitwise` field equals 0xFFFFFFFF, so the mask
    // is a no-op. The NoName capture has the
    // field at 0x00000001 — clearly a flag, not a mask — so we treat it as
    // opaque and emit the full crc32 on rewrite.
    //
    // Samples: docs/packets/references/npc_dialogue (WithName),
    //          docs/packets/NpcDialogue_NoName.txt (NoName).
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
    private uint _bitwise;           // mask (WithName) / flag (NoName)
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

    private uint CalculateCrc(string text)
    {
        var crc = new Crc32();
        crc.Append(Encoding.UTF8.GetBytes(text));
        var full = BitConverter.ToUInt32(crc.GetHashAndReset());
        // NoName treats `_bitwise` as a flag, not a mask — emit the full crc.
        // WithName ANDs with `_bitwise` (in observed captures it's 0xFFFFFFFF, so this is a no-op).
        return _variant == Variant.NoName ? full : (full & _bitwise);
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
