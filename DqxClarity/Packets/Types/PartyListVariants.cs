using System.Text;

namespace DqxClarity.Packets.Types;

//

// Each variant is the same shape with different header sizes / slot widths:
//   variant 2 (0x03 / 0x5408): header 80 bytes, name in a fixed 41-byte slot (no length prefix)
//   variant 3 (0xa1 / 0x2711): header 78 bytes, length u32 then cstring
//   variant 4 (0xa1 / 0x8a6a): header 326 bytes, length u32 then cstring
//
// Names looked up in m00 'local_player_names' first; romanizer fallback on miss.
public sealed class PartyList2Packet : IPacket
{
    private const int HeaderBytes = 80;
    private const int NameSlotBytes = 41;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public PartyList2Packet(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < HeaderBytes + NameSlotBytes) return;

        var nameBytes = _raw.AsSpan(HeaderBytes, NameSlotBytes);
        var nullIdx = nameBytes.IndexOf((byte)0);
        var nameLen = nullIdx >= 0 ? nullIdx : NameSlotBytes;
        var jpName = Encoding.UTF8.GetString(nameBytes[..nameLen]);
        if (string.IsNullOrEmpty(jpName)) return;

        var dict = _deps.M00Dict("local_player_names");
        var translated = dict.TryGetValue(jpName, out var en2) && !string.IsNullOrEmpty(en2)
            ? en2
            : _deps.Romanizer.ToRomaji(jpName, 11);
        if (translated == jpName) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_raw.AsSpan(0, HeaderBytes).ToArray());
        var en = Encoding.UTF8.GetBytes(translated);
        if (en.Length > NameSlotBytes - 1) en = en[..(NameSlotBytes - 1)];
        writer.WriteBytes(en);
        writer.WriteBytes(new byte[NameSlotBytes - en.Length]);
        writer.WriteBytes(_raw.AsSpan(HeaderBytes + NameSlotBytes).ToArray());
        ModifiedData = writer.Build();
    }
}

public sealed class PartyList3Packet : IPacket
{
    private const int HeaderBytes = 78;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public PartyList3Packet(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build() => PartyListVariantsCommon.BuildWithLengthPrefix(_raw, _deps, HeaderBytes, m => ModifiedData = m);
}

public sealed class PartyList4Packet : IPacket
{
    private const int HeaderBytes = 326;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public PartyList4Packet(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build() => PartyListVariantsCommon.BuildWithLengthPrefix(_raw, _deps, HeaderBytes, m => ModifiedData = m);
}

internal static class PartyListVariantsCommon
{
    // Shared layout for variants 3 + 4: header, name_length u32, name cstring, remainder.
    public static void BuildWithLengthPrefix(byte[] raw, PacketDependencies deps, int headerBytes, Action<byte[]> setModified)
    {
        if (raw.Length < headerBytes + 4) return;

        var reader = new PacketReader(raw);
        var header = reader.ReadBytes(headerBytes).ToArray();
        var nameLength = reader.ReadU32();
        if (nameLength == 0) return;

        var jpName = reader.ReadCString();
        var remainder = reader.RemainingBytes().ToArray();

        var dict = deps.M00Dict("local_player_names");
        var translated = dict.TryGetValue(jpName, out var en) && !string.IsNullOrEmpty(en)
            ? en
            : deps.Romanizer.ToRomaji(jpName, 11);
        if (string.IsNullOrEmpty(translated) || translated == jpName) return;

        var bytes = Encoding.UTF8.GetBytes(translated);
        var writer = new PacketWriter();
        writer.WriteBytes(header);
        writer.WriteU32((uint)(bytes.Length + 1));
        writer.WriteCString(translated);
        writer.WriteBytes(remainder);
        setModified(writer.Build());
    }
}
