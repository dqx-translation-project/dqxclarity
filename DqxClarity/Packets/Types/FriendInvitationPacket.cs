using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// A friend-request invitation notification. Same opcode family (0x0d) as
// TeamJoinMessagePacket (marker 0x11c1) and structurally near-identical:
// a doubled-tick-id ("BF 02 55 01" twice) immediately precedes the
// requester's name, same as every other packet in this family.
//
// Layout (after opcode + marker):
//   header        40 bytes (passthrough — mostly zero/small counters,
//                 ending in the doubled 4-byte id)
//   player_name   cstring (utf-8, null-terminated, no length prefix) —
//                 confirmed exact match against "ジュース" in the sample
//                 capture
//   remainder     rest of payload (passthrough, 118 bytes, unexamined —
//                 contains a run of bytes that happens to spell the ASCII
//                 word "itation" immediately after the name; that's
//                 coincidental binary data, not a second text field — it's
//                 not japanese so IsTextJapanese/TryResolveName would
//                 never touch it anyway, and it fails to decode as valid
//                 text past the 7th byte)
//
// Resolved the same way TeamJoinMessagePacket/EntityPacket resolve a
// Player entity's name: 'local_player_names' m00 dict first, romaji
// fallback on miss.
//
// This packet family is now a CONFIRMED crash risk if the name field is
// allowed to change the packet's total length — see TeamJoinMessagePacket's
// doc comment for the byte-level proof (a same-opcode-family packet crashed
// the client when a shorter romaji name shifted every field after it).
// Applying the fix here from the start rather than waiting for a repro:
// the name is written into a slot fixed at the ORIGINAL name's byte length
// (+1 for the terminator) — translations that are shorter get zero-padded
// out to that width, translations that are longer get truncated to fit.
// Every offset after the name field is therefore identical to the
// original, regardless of what the translation is.
//
// Sample: docs/packets/references/friend_invitation
public sealed class FriendInvitationPacket : IPacket
{
    private const int HeaderBytes = 40;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _playerName = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public FriendInvitationPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes) return;
        var reader = new PacketReader(_raw);
        _header     = reader.ReadBytes(HeaderBytes).ToArray();
        _playerName = reader.ReadCString();
        _remainder  = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var newName = ResolveName(_playerName);
        if (newName == _playerName) return;

        // Fixed-width slot: original name's byte length + 1 (null
        // terminator). See the class doc comment — this packet family
        // crashes the client if the name field is allowed to change the
        // overall packet length.
        var nameSlotBytes = Encoding.UTF8.GetByteCount(_playerName) + 1;
        var newNameBytes = Encoding.UTF8.GetBytes(newName);
        if (newNameBytes.Length > nameSlotBytes - 1)
            newNameBytes = newNameBytes[..(nameSlotBytes - 1)];

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteBytes(newNameBytes);
        writer.WriteBytes(new byte[nameSlotBytes - newNameBytes.Length]); // null terminator + padding
        writer.WriteBytes(_remainder);

        ModifiedData = writer.Build();
    }

    private string ResolveName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        var dict = _deps.M00Dict("local_player_names");
        if (dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known)) return known;
        return _deps.Romanizer.ToRomaji(japanese);
    }
}
