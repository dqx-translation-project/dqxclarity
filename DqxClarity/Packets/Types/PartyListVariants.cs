using System.Text;

namespace DqxClarity.Packets.Types;

//

// Each variant is the same shape with different header sizes / slot widths:
//   variant 2 (0x03 / 0x5408): header 84 bytes (80 before the 8.1 update), name in a fixed
//                              41-byte slot (no length prefix)
//   variant 3 (0xa1 / 0x2711): header 78 bytes, length u32 then cstring
//   variant 4 (0xa1 / 0x8a6a): header 326 bytes, length u32 then cstring
//
// Names looked up in m00 'local_player_names' first, then
// 'custom_npc_name_overrides', romanizer fallback on miss in both -- see
// PartyListPacket's doc comment for why (an NPC companion can occupy a
// party slot with no player-name-dict entry to match).
public sealed class PartyList2Packet : IPacket
{
    private const int HeaderBytes = 84;
    private const int NameSlotBytes = 41;

    // The slot is read up to its first null, but a character id sits at +36
    // inside it (D9 AF 11 0D in a capture of the player's own entry). Only the
    // old name's bytes are cleared and the new name written over them, so
    // nothing else in the slot is touched, and a name is cut at 35 bytes so it
    // can never run into the id.
    private const int MaxNameBytes = 35;

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

        if (!PacketText.TryReadSlot(_raw.AsSpan(HeaderBytes, NameSlotBytes), out var jpName))
            throw new PacketLayoutException(
                $"the {NameSlotBytes}-byte name slot at offset {HeaderBytes} does not hold text; the layout has probably changed",
                HeaderBytes);
        if (string.IsNullOrEmpty(jpName)) return;

        var playerDict = _deps.M00Dict("local_player_names");
        var npcOverrideDict = _deps.M00Dict("custom_npc_name_overrides");
        var translated = playerDict.TryGetValue(jpName, out var en2) && !string.IsNullOrEmpty(en2)
            ? en2
            : npcOverrideDict.TryGetValue(jpName, out var npcEn2) && !string.IsNullOrEmpty(npcEn2)
                ? npcEn2
                : _deps.Romanizer.ToRomaji(jpName, 11);
        if (translated == jpName) return;

        var en = Encoding.UTF8.GetBytes(translated);
        if (en.Length > MaxNameBytes) en = en[..MaxNameBytes];

        // Same length as the original: clear the old name (and its null), write
        // the new one, leave every other byte alone.
        var result = (byte[])_raw.Clone();
        var oldLength = Encoding.UTF8.GetByteCount(jpName);
        Array.Clear(result, HeaderBytes, Math.Min(oldLength + 1, MaxNameBytes + 1));
        Buffer.BlockCopy(en, 0, result, HeaderBytes, en.Length);
        result[HeaderBytes + en.Length] = 0;

        ModifiedData = result;
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

        var playerDict = deps.M00Dict("local_player_names");
        var npcOverrideDict = deps.M00Dict("custom_npc_name_overrides");
        var translated = playerDict.TryGetValue(jpName, out var en) && !string.IsNullOrEmpty(en)
            ? en
            : npcOverrideDict.TryGetValue(jpName, out var npcEn) && !string.IsNullOrEmpty(npcEn)
                ? npcEn
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
