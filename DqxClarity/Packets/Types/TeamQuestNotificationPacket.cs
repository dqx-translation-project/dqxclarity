namespace DqxClarity.Packets.Types;

// A notification banner naming a single Team Quest -- opcode 0x3d, same as
// TeamQuestPacket (marker 0x16b6), but a different marker (0x31dc, or 0x760c
// -- see below) and a much smaller, single-name layout rather than the
// paired name+description x2 structure that packet uses.
//
// SECOND MARKER (0x760c): a later capture ("悪霊の神々討伐！") arrived under
// marker 0x760c instead of the original 0x31dc -- looks like a game update
// changed the identifier for this notification, not a new packet type. The
// payload was byte-for-byte the same shape as the two 0x31dc samples below,
// right down to the same DA 7D 1E 02 constant at header offset 8, so both
// markers are routed to this same class rather than treating 0x760c as
// something new. Not yet confirmed whether 0x31dc still occurs on the
// current client or has been fully replaced -- both are kept wired in until
// that's known.
//
// Layout (after opcode + marker), confirmed identical across all captures
// (both markers):
//   header   12 bytes (passthrough) -- a little-endian u32 at offset 0
//            that differs between the two captures (1 vs 3, quest slot/
//            objective index?), 4 zero bytes, then a 4-byte field (DA 7D
//            1E 02) that's IDENTICAL in both captures despite being taken
//            4 seconds apart -- likely a team/session id rather than
//            anything quest-specific, but unconfirmed
//   name     cstring (utf-8, null-terminated) -- the LAST field in the
//            packet, nothing follows it in either capture
//
// Because the name is the trailing field with nothing after it that a
// length change could shift, this is safe to let grow or shrink freely --
// same category as SiblingNamePacket/NpcDialoguePacket, not the
// fixed-offset roster family. GamePacket's outer wire-frame resize handles
// the length change.
//
// Per the user: Team Quest names should ONLY be looked up in the m00
// 'custom_team_quests' dict (the same dict TeamQuestPacket uses) with NO
// romanizer fallback -- a miss passes through as the original Japanese
// untouched, exactly like TeamQuestPacket's own quest name/description
// fields.
//
// Samples: docs/packets/references/team_quest_notification_1 (キラ拾い探索！,
//            marker 0x31dc),
//          docs/packets/references/team_quest_notification_2 (鳥系討伐！,
//            marker 0x31dc)
//          live capture, marker 0x760c (悪霊の神々討伐！) -- no reference dump
//            saved to docs/packets/references yet
public sealed class TeamQuestNotificationPacket : IPacket
{
    private const int HeaderBytes = 12;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _name = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public TeamQuestNotificationPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes) return;
        var reader = new PacketReader(_raw);
        _header = reader.ReadBytes(HeaderBytes).ToArray();
        _name = reader.ReadCString();
        _remainder = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var dict = _deps.M00Dict("custom_team_quests");
        var newName = dict.GetValueOrDefault(_name, _name);
        if (newName == _name) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(newName);
        writer.WriteBytes(_remainder);
        ModifiedData = writer.Build();
    }
}
