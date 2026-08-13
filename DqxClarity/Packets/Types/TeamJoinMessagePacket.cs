using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The actual "<player> joined the Team!" toast/chat-log message. Same
// opcode family (0x0d) as TeamJoinNotificationPacket (marker 0x9804), but a
// different marker (0x11c1) and — per the user, who reported the existing
// packet "doesn't do anything even after modifying it" — this is the one
// that's actually responsible for the visible notification. Left
// TeamJoinNotificationPacket in place rather than replacing it: whatever
// 0x9804 actually is, it's still a distinct, real packet, just not this one.
//
// Layout (after opcode + marker):
//   header        28 bytes (passthrough — mostly zero/small counters; the
//                 last 8 bytes are a 4-byte id doubled back-to-back
//                 ("B7 00 54 01" twice), the same doubled-tick-field shape
//                 seen bracketing names in NpcDialoguePacket/
//                 PartyInvitationPacket/MailMessagePacket)
//   player_name   cstring (utf-8, null-terminated, no length prefix) —
//                 confirmed exact match against "ローイイット" in the
//                 sample capture
//   remainder     rest of payload (passthrough, 107 bytes, unexamined —
//                 no length-looking field was spotted immediately
//                 preceding the name, same reasoning as the sibling packet)
//
// Resolved the same way TeamJoinNotificationPacket/EntityPacket resolve a
// Player entity's name: 'local_player_names' m00 dict first, romaji
// fallback on miss.
//
// CONFIRMED CRASH, now fixed: an earlier version of this class let the name
// field grow/shrink freely (relying on GamePacket's outer wire-frame resize,
// same as NpcDialoguePacket/MailMessagePacket/etc.). That assumption holds
// for actual dialogue/text-box packets, but not here -- a capture with
// "やんもら" (12 utf-8 bytes) translated to "Yanmora" (7 bytes) crashed the
// game. Byte-level comparison of the original vs. modified wire capture
// showed the outer size byte *was* correctly recalculated (159 -> 154) and
// every field after the name shifted left by exactly 5 bytes, content
// unchanged -- so the bug isn't in our reconstruction, it's that the
// client evidently reads this message's fields (name plus whatever follows
// it) at fixed offsets from the packet start rather than scanning for the
// name's null terminator. Shrinking the name shifts every later field out
// from under a fixed-offset reader.
//
// Fix: never change this packet's total length. The name is written into a
// slot whose width is fixed at the ORIGINAL name's byte length (+1 for the
// terminator) for this specific packet -- translations that are shorter get
// zero-padded out to that width, translations that are longer get
// truncated to fit. Every offset after the name field is therefore
// identical to the original, regardless of what the translation is.
//
// Sample: docs/packets/references/team_join_message,
//         docs/packets/references/team_join_message_crash_original +
//         _crash_modified (the "やんもら"/"Yanmora" original+modified pair
//         that crashed, saved as proof of the bug this fix addresses)
public sealed class TeamJoinMessagePacket : IPacket
{
    private const int HeaderBytes = 28;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _playerName = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public TeamJoinMessagePacket(byte[] payloadData, PacketDependencies deps)
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
        // terminator). See the class doc comment for why -- this packet
        // crashed the client when the name field was allowed to change the
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
