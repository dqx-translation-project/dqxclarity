using System.Text;

namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   header                28 bytes (player_count u8 at offset 24)
//   member[player_count]: { entry_header 21 bytes, name 20-byte fixed slot }
//   remainder             (rest of payload)
//
// Names looked up in m00 'local_player_names' first; romanizer fallback on miss.
// Name slot is 20 bytes (19 usable + null terminator).
public sealed class SupportPartyListPacket : IPacket
{
    private const int HeaderBytes = 28;
    private const int PlayerCountOffsetInHeader = 24;
    private const int MemberEntryHeader = 21;
    private const int NameSlotBytes = 20;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public SupportPartyListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < HeaderBytes) return;
        var reader = new PacketReader(_raw);

        var header = reader.ReadBytes(HeaderBytes).ToArray();
        var playerCount = header[PlayerCountOffsetInHeader];
        if (playerCount == 0) return;

        var entries = new List<(byte[] Header, string Name)>();
        for (var i = 0; i < playerCount; i++)
        {
            if (reader.Remaining < MemberEntryHeader + NameSlotBytes) return;
            var entryHeader = reader.ReadBytes(MemberEntryHeader).ToArray();
            var nameSlot = reader.ReadBytes(NameSlotBytes);
            var nullIdx = nameSlot.IndexOf((byte)0);
            var nameLen = nullIdx >= 0 ? nullIdx : NameSlotBytes;
            var jpName = Encoding.UTF8.GetString(nameSlot[..nameLen]);
            entries.Add((entryHeader, jpName));
        }
        var remainder = reader.RemainingBytes().ToArray();

        var dict = _deps.M00Dict("local_player_names");
        var anyChange = false;
        var writer = new PacketWriter();
        writer.WriteBytes(header);
        foreach (var (entryHeader, jpName) in entries)
        {
            writer.WriteBytes(entryHeader);
            var translated = dict.TryGetValue(jpName, out var en) && !string.IsNullOrEmpty(en)
                ? en
                : _deps.Romanizer.ToRomaji(jpName, 11);
            if (translated != jpName) anyChange = true;
            var bytes = Encoding.UTF8.GetBytes(translated);
            if (bytes.Length > NameSlotBytes - 1) bytes = bytes[..(NameSlotBytes - 1)];
            writer.WriteBytes(bytes);
            writer.WriteBytes(new byte[NameSlotBytes - bytes.Length]);
        }
        writer.WriteBytes(remainder);
        if (anyChange) ModifiedData = writer.Build();
    }
}
