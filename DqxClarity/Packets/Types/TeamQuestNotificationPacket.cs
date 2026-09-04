namespace DqxClarity.Packets.Types;

// A notification banner naming a single Team Quest -- opcode 0x3d, same as
// TeamQuestPacket (marker 0x16b6), but a different marker (0x31dc) and a
// much smaller, single-name layout rather than the paired name+description
// x2 structure that packet uses.
//
// Layout (after opcode + marker), confirmed identical in both sample
// captures:
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
// Samples: docs/packets/references/team_quest_notification_1 (キラ拾い探索！),
//          docs/packets/references/team_quest_notification_2 (鳥系討伐！)
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
