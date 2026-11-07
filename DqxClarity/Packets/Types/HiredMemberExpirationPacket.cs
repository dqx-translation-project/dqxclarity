using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// Notification shown when a hired party member (a support character hired
// from another player) is about to expire or has expired -- opcode 0x95,
// marker 0x732B. Not to be confused with MailSenderNamePacket, which shares
// this marker but a different opcode (0x97).
//
// Layout (after opcode + marker), confirmed identical in shape across both
// captures on hand:
//   header        12 bytes (passthrough -- Data[0:4] is a u32 that differs
//                 between the two captures (0 vs 1), maybe a per-notification
//                 sequence counter; Data[4:8] was 0 in both; Data[8] was
//                 0x7E (126) in both -- possibly a notification-type
//                 constant the same way SugorokuItemNotificationPacket has
//                 one; Data[9:12] was 0 in both)
//   player_name   cstring (utf-8, null-terminated, no length prefix)
//   remainder     everything after the name's null terminator (passthrough)
//
// CONFIRMED FIXED-SIZE PACKET: both captures are exactly 36 bytes of Data
// despite carrying different-length names (しょーた, 12 utf-8 bytes, vs
// みーあ, 9 utf-8 bytes) -- the byte(s) immediately after each name's null
// terminator are NOT the same between captures either (4 zero bytes in one,
// "09 24" followed by zeros in the other), which looks like leftover
// stale-buffer content the same way NpcChatBubblePacket's tail was proven to
// be, rather than meaningful data. But the LAST 8 bytes of Data are
// byte-for-byte IDENTICAL across both captures ("8B 30 7B 08 67 02 00 00")
// despite the names differing -- too consistent to be garbage, most likely a
// real fixed-position field (hire slot id / duration / similar). Given
// TeamJoinMessagePacket's confirmed crash (translating a name that changed
// the packet's total length, or shifted anything after it, broke the
// client because it reads at least some fields at offsets fixed from the
// packet start rather than scanning for a name's null terminator), this is
// treated the same defensive way as FriendRequestAcceptedPacket: the
// translated name is written back into a slot pinned at exactly the
// ORIGINAL name's byte width (+1 for the terminator), truncated if the
// translation is longer, zero-padded if shorter, so `remainder` -- and
// whatever real field lives in that trailing 8 bytes -- never moves and the
// packet's total length never changes, regardless of what the true
// underlying buffer size turns out to be.
//
// player_name resolved the same way every other player name in this
// codebase is: m00 'local_player_names' dict first, romaji fallback when
// the name isn't in the dict.
//
// Samples: docs/packets/references/hired_member_expiration_shota,
//          docs/packets/references/hired_member_expiration_mia
public sealed class HiredMemberExpirationPacket : IPacket
{
    private const int HeaderBytes = 12;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _playerName = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public HiredMemberExpirationPacket(byte[] payloadData, PacketDependencies deps)
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
        // terminator). See the class doc comment -- this packet is a fixed
        // total size and at least one field after the name looks real
        // (identical across both captures despite different names), so the
        // translation must never change the packet's length or shift
        // anything after it.
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
