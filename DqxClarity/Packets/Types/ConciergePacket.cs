namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   header_data          221 bytes (passthrough)
//   name                 cstring (utf-8)
//   remaining            (passthrough)
//
// Name is looked up in the m00 dict {custom_concierge_mail_names, local_mytown_names};
// if missing we fall back to the romanizer. We prepend '\x04' to the new name to
// suppress the GM-face icon the game shows for unknown senders.
public sealed class ConciergePacket : IPacket
{
    private const int HeaderBytes = 221;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _name = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public ConciergePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        var reader = new PacketReader(_raw);
        _header = reader.ReadBytes(HeaderBytes).ToArray();
        _name = reader.ReadCString();
        _remainder = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var dict = _deps.M00Dict("custom_concierge_mail_names", "local_mytown_names");
        var translated = dict.TryGetValue(_name, out var en) && !string.IsNullOrEmpty(en)
            ? en
            : _deps.Romanizer.ToRomaji(_name);

        if (translated == _name) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString("\x04" + translated);
        writer.WriteBytes(_remainder);
        ModifiedData = writer.Build();
    }
}
