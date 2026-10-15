using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// TRANSLATION CURRENTLY DISABLED -- CONFIRMED CRASH. A live capture of this
// packet (joining player えびな, translated to "Ebina") crashed the DQX client.
// Comparing the original and the translated bytes shows the rewrite was exactly
// what this class intends: same 30-byte Data length, same 33-byte frame, header
// and id identical, the 4 tail bytes at the same offset, only the 9 name bytes
// changed (the name pinned to its original width, zero-padded). So this is NOT
// the usual "translation changed the length or moved a later field" crash --
// the same situation as SlimeRaceNameListPacket, where the content landing in
// the field, not its position or width, is what the client rejects. Leading
// theory, unconfirmed: the client may treat a name that starts with an ASCII
// letter specially (EntityPacket needs a \x04 prefix on translated names so the
// game doesn't show the GM-face icon), and this UI may crash on it. Another
// possibility is that the client looks the joining player up by the original
// name. FriendRequestAcceptedPacket (same opcode, same header shape) may have
// crashed the same way -- one report, not confirmed. Build() is a deliberate
// no-op until the real cause is known, so the packet passes through
// untouched. The parsing and the old rewrite are kept (commented out) for
// whatever fix comes next; do not re-enable without new evidence of what is
// safe here.
//
// The notice that someone has joined a chat room you're in -- opcode 0x0D,
// marker 0xCDC7. Carries the joining player's name. (Same opcode as the other
// 0x0D communication packets -- TeamJoinNotification, FriendRequestAccepted,
// the Chat_* messages -- but a different marker; the (opcode, marker) pair is
// what identifies it.)
//
// Layout (after opcode + marker), from one capture (33 bytes of Data, joining
// player ヴァイス):
//   zeros        12 bytes -- all zero in the capture. Passthrough.
//   player_id    u32 -- BB E5 74 05 in the capture; looks like the joining
//                player's id (the same kind of id ItemHistoryNamePacket's id
//                field carries). Passthrough.
//   player_name  cstring (utf-8, null-terminated, no length prefix)
//   tail         4 bytes -- CA B5 36 01 in the capture. Passthrough, meaning
//                unknown (an id or a tick-like value).
//
// The name is followed immediately by the 4 tail bytes, and this is an
// opcode-0x0D notification -- the family (TeamJoinMessagePacket,
// FriendRequestAcceptedPacket, FriendInvitationPacket...) where a translated
// name that changes the packet's length, or moves anything after it, is a
// confirmed crash/corruption risk. So the name is written into a slot pinned
// to the ORIGINAL name's byte width (+1 for the terminator): a shorter
// translation is zero-padded out to that width, a longer one is cut (on a
// utf-8 character boundary), and the tail stays at exactly the same offset.
// The packet's total length never changes.
//
// (An earlier version let the name grow/shrink, on the theory that the
// terminator-then-tail shape meant a plain null-terminated string. It was
// changed to this fixed-width form to match the rest of the family.)
//
// player_name is a player-chosen character name, so it resolves like every
// other player name in this codebase: m00 'local_player_names' first, romaji
// fallback on a miss. No \x04 prefix -- that's an EntityPacket nameplate
// trick, not a general player-name convention.
//
// Samples: docs/packets/references/chat_room_join (ヴァイス),
//          docs/packets/references/chat_room_join_crash_original (えびな) and
//          docs/packets/references/chat_room_join_crash_modified (the
//          "Ebina" rewrite that crashed the client)
public sealed class ChatRoomJoinPacket : IPacket
{
    private const int HeaderBytes = 16; // 12 zero bytes + u32 player id

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _playerName = "";
    private byte[] _tail = Array.Empty<byte>();
    private bool _parsed;

    public byte[]? ModifiedData { get; private set; }

    public ChatRoomJoinPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes + 1) return;
        var reader = new PacketReader(_raw);
        _header     = reader.ReadBytes(HeaderBytes).ToArray();
        _playerName = reader.ReadCString();
        _tail       = reader.RemainingBytes().ToArray();
        _parsed = true;
    }

    public void Build()
    {
        // DISABLED -- see the class doc comment. ModifiedData stays null so
        // the packet passes through untouched.
        //
        // if (!_parsed) return;
        //
        // var newName = ResolveName(_playerName);
        // if (newName == _playerName) return;
        //
        // // Fixed-width slot: original name's byte length + 1 (terminator).
        // var slotBytes = Encoding.UTF8.GetByteCount(_playerName) + 1;
        // var newBytes = TruncateUtf8(Encoding.UTF8.GetBytes(newName), slotBytes - 1);
        //
        // var writer = new PacketWriter();
        // writer.WriteBytes(_header);
        // writer.WriteBytes(newBytes);
        // writer.WriteBytes(new byte[slotBytes - newBytes.Length]); // terminator + padding
        // writer.WriteBytes(_tail);
        //
        // ModifiedData = writer.Build();
    }

    private string ResolveName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        var dict = _deps.M00Dict("local_player_names");
        if (dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known)) return known;
        return _deps.Romanizer.ToRomaji(japanese);
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
