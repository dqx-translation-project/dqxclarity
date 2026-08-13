using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The "you are now friends with <player>" notification shown when someone
// accepts (or you accept) a friend request. Same opcode family (0x0d) as
// FriendInvitationPacket (marker 0x9393) and TeamJoinMessagePacket (marker
// 0x11c1), same shape, just simpler -- no doubled-tick-id, and the name is
// the very last thing in the packet (null terminator, then nothing).
//
// Layout (after opcode + marker):
//   header        16 bytes (passthrough — mostly zero/small counters)
//   player_name   cstring (utf-8, null-terminated, no length prefix) —
//                 confirmed exact match against "ガロッシュ" in the sample
//                 capture
//   (nothing follows the terminator — it's the last byte of the packet)
//
// Resolved the same way TeamJoinMessagePacket/FriendInvitationPacket
// resolve a Player entity's name: 'local_player_names' m00 dict first,
// romaji fallback on miss.
//
// This whole opcode-0x0d notification family is a CONFIRMED crash/corruption
// risk if a translated name is allowed to change the packet's total length
// — see TeamJoinMessagePacket's doc comment for the crash proof, and
// PartyInvitationPacket's for a case where changing a name's *position*
// (not just the packet's length) corrupted an unrelated field and made the
// name render blank. Applying the same fix here from the start: the name
// is written into a slot fixed at the ORIGINAL name's byte length (+1 for
// the terminator) — translations that are shorter get zero-padded out to
// that width, translations that are longer get truncated to fit. Since
// nothing follows the name in this packet, this also means the packet's
// total length never changes at all.
//
// Sample: docs/packets/references/friend_request_accepted
public sealed class FriendRequestAcceptedPacket : IPacket
{
    private const int HeaderBytes = 16;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _playerName = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public FriendRequestAcceptedPacket(byte[] payloadData, PacketDependencies deps)
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
        // crashes/corrupts if the name field is allowed to change the
        // overall packet length or shift what follows it.
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
