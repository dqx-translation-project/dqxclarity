namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   header_data   76 bytes (passthrough)
//   quest_1_name  cstring
//   quest_1_desc  cstring
//   quest_2_name  cstring
//   quest_2_desc  cstring
//
// Team quests always come in pairs. All four strings are looked up in m00
// 'custom_team_quests'; misses pass through as original japanese.
public sealed class TeamQuestPacket : IPacket
{
    private const int HeaderBytes = 76;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _quest1Name = "";
    private string _quest1Desc = "";
    private string _quest2Name = "";
    private string _quest2Desc = "";

    public byte[]? ModifiedData { get; private set; }

    public TeamQuestPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        var reader = new PacketReader(_raw);
        _header    = reader.ReadBytes(HeaderBytes).ToArray();
        _quest1Name = reader.ReadCString();
        _quest1Desc = reader.ReadCString();
        _quest2Name = reader.ReadCString();
        _quest2Desc = reader.ReadCString();
    }

    public void Build()
    {
        var dict = _deps.M00Dict("custom_team_quests");

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(dict.GetValueOrDefault(_quest1Name, _quest1Name));
        writer.WriteCString(dict.GetValueOrDefault(_quest1Desc, _quest1Desc));
        writer.WriteCString(dict.GetValueOrDefault(_quest2Name, _quest2Name));
        writer.WriteCString(dict.GetValueOrDefault(_quest2Desc, _quest2Desc));

        ModifiedData = writer.Build();
    }
}
