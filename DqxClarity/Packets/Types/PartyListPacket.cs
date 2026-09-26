using System.Text;

namespace DqxClarity.Packets.Types;

//

// Fixed-offset layout:
//   offset 0x20 (32) : party_count   u8
//   offset 0x64 (100): first member name (cstring inside an 18-byte slot)
//   subsequent members at +0x2FC stride
//
// Names looked up in m00 'local_player_names' first, then
// 'custom_npc_name_overrides', romanizer fallback on miss in both --
// same resolution order as EntityPacket's Fellow case (type byte 0x85).
// Most party members are real players, but some quests/events add an NPC
// companion directly to the active party (a "fellow"-style slot, not a
// hired one specifically) with no player-name-dict entry to match, so
// without the override dict here they'd fall through to a bare romaji
// transliteration instead of their curated translated name.
public sealed class PartyListPacket : IPacket
{
    private const int PartyCountOffset    = 0x20;
    private const int FirstNameOffset     = 0x64;
    private const int EntryStride         = 0x2FC;
    private const int NameBufferSize      = 18;
    private const int MaxNameLength       = 11;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public PartyListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length <= PartyCountOffset) return;
        var partyCount = _raw[PartyCountOffset];
        if (partyCount == 0) return;

        var buf = (byte[])_raw.Clone();
        var playerDict = _deps.M00Dict("local_player_names");
        var npcOverrideDict = _deps.M00Dict("custom_npc_name_overrides");
        var changed = false;

        for (var i = 0; i < partyCount; i++)
        {
            var nameOff = FirstNameOffset + (i * EntryStride);
            if (nameOff + NameBufferSize > buf.Length) break;

            var end = nameOff;
            while (end < buf.Length && end < nameOff + NameBufferSize && buf[end] != 0) end++;
            if (end == nameOff) continue;

            var jpName = Encoding.UTF8.GetString(buf, nameOff, end - nameOff);
            if (string.IsNullOrEmpty(jpName)) continue;

            var translated = playerDict.TryGetValue(jpName, out var en) && !string.IsNullOrEmpty(en)
                ? en
                : npcOverrideDict.TryGetValue(jpName, out var npcEn) && !string.IsNullOrEmpty(npcEn)
                    ? npcEn
                    : _deps.Romanizer.ToRomaji(jpName, MaxNameLength);
            if (translated == jpName) continue;
            if (translated.Length > MaxNameLength) translated = translated[..MaxNameLength];

            var enBytes = Encoding.UTF8.GetBytes(translated);
            if (enBytes.Length > NameBufferSize) enBytes = enBytes[..NameBufferSize];

            for (var b = 0; b < NameBufferSize; b++)
                buf[nameOff + b] = b < enBytes.Length ? enBytes[b] : (byte)0;
            changed = true;
        }

        if (changed) ModifiedData = buf;
    }
}
