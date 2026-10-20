using System.Text;

namespace DqxClarity.Packets.Types;

//

// Fixed-offset layout:
//   offset 0x20 (32) : party_count   u8
//   offset 0x68 (104): first member name (cstring inside an 18-byte slot)
//   subsequent members at +0x304 (772) stride
//   the whole packet is exactly 38 + party_count x 772 bytes
//
// These were 0x64 / 0x2FC (100 / 764) until the 8.1 update, which grew each
// member record by 8 bytes and the front of the packet by 4 -- every name then
// sat at the wrong offset, so the (empty) bytes found there meant nothing was
// translated and nothing looked wrong. Confirmed from two captures: a party of
// 1 (810 bytes) and a party of 4 (3126 bytes, names at 104, 876, 1648, 2420).
// The exact-size check below is there so the next change is noticed instead
// of silently skipped.
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
    private const int FirstNameOffset     = 0x68;
    private const int EntryStride         = 0x304;
    private const int FixedBytes          = 38; // packet size outside the member records
    private const int NameBufferSize      = 18;
    private const int MaxNameLength       = 11;
    private const int MaxPlausibleCount   = 24;

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

        // A count that big is the count byte being read from the wrong place.
        if (partyCount > MaxPlausibleCount)
            throw new PacketLayoutException(
                $"party count {partyCount} at offset {PartyCountOffset} is not plausible (max {MaxPlausibleCount})",
                PartyCountOffset);

        var expectedLength = FixedBytes + (partyCount * EntryStride);
        if (_raw.Length != expectedLength)
            throw new PacketLayoutException(
                $"{_raw.Length} bytes for a party of {partyCount}, expected {FixedBytes} + {partyCount} x {EntryStride} = {expectedLength}; " +
                "the member record size has probably changed");

        var buf = (byte[])_raw.Clone();
        var playerDict = _deps.M00Dict("local_player_names");
        var npcOverrideDict = _deps.M00Dict("custom_npc_name_overrides");
        var changed = false;
        var namesFound = 0;
        var slotsNotText = 0;

        for (var i = 0; i < partyCount; i++)
        {
            var nameOff = FirstNameOffset + (i * EntryStride);
            if (nameOff + NameBufferSize > buf.Length) break;

            // If what is in the slot isn't text it isn't a name (the entries
            // aren't where we think they are), so don't write over it.
            if (!PacketText.TryReadSlot(buf.AsSpan(nameOff, NameBufferSize), out var jpName))
            {
                slotsNotText++;
                continue;
            }
            if (string.IsNullOrEmpty(jpName)) continue;
            namesFound++;

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

        // Every slot that held anything held non-text: the entry layout has
        // moved. Nothing was rewritten, so leave the packet alone and report.
        if (namesFound == 0 && slotsNotText > 0)
            throw new PacketLayoutException(
                $"none of the {slotsNotText} non-empty name slots (first at offset {FirstNameOffset}, " +
                $"every {EntryStride} bytes) hold text; the entry layout has probably changed");

        if (changed) ModifiedData = buf;
    }
}
