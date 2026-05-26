namespace DqxClarity.Packets.Types;

//

// Handles weekly quest request windows (e.g. Demon Lord's Ghostwriter,
// Sky High Fitness) that show the quest name and objective.
//
// Layout (after opcode + marker):
//   header_data      60 bytes (passthrough)
//   quest_name       cstring
//   quest_objective  cstring
//   remaining        (passthrough)
//
// Both strings are looked up in m00 'custom_episode_request_book' and
// 'custom_trainee_logbook' (merged); misses pass through as original japanese.
public sealed class WeeklyRequestPacket : IPacket
{
    private const int HeaderBytes = 60;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _questName = "";
    private string _questObjective = "";
    private byte[] _remaining = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public WeeklyRequestPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        var reader = new PacketReader(_raw);
        _header         = reader.ReadBytes(HeaderBytes).ToArray();
        _questName      = reader.ReadCString();
        _questObjective = reader.ReadCString();
        _remaining      = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var dict = _deps.M00Dict("custom_episode_request_book", "custom_trainee_logbook");

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(dict.GetValueOrDefault(_questName, _questName));
        writer.WriteCString(dict.GetValueOrDefault(_questObjective, _questObjective));
        writer.WriteBytes(_remaining);

        ModifiedData = writer.Build();
    }
}
