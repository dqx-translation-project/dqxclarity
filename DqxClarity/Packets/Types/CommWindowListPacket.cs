using System.Text;

namespace DqxClarity.Packets.Types;

//

// Communication window (team/party member list). Fixed-offset layout: the player
// count lives at offset 12 (u32); entries start at offset 16, each is 217 bytes
// wide, with the name starting at +112 inside the entry, filling a 19-byte slot
// (+ null terminator = 20 total). Names longer than 11 ascii chars crash the game's
// chat window, so we cap at 11 and pad with nulls.
//
// Entry size / name position were 213 / +108 until the 8.1 update, which added
// 4 bytes in front of the name (and dropped the 18-byte trailer, so a packet is
// now exactly 16 + count x 217 bytes). Found from a mismatch report: a capture
// with 20 entries had all 20 names at 128 + n x 217. Bytes after a name's null
// inside its slot are stale leftovers from longer names (the slot isn't zeroed),
// which is normal.
public sealed class CommWindowListPacket : IPacket
{
    private const int PlayerCountOffset = 12;
    private const int FirstEntryOffset = 16;
    private const int EntrySize = 217;
    private const int NamePositionInEntry = 112;
    private const int NameBufferSize = 19;
    private const int MaxNameLength = 11;
    private const uint MaxPlausibleCount = 256;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;
    private readonly uint _playerCount;

    public byte[]? ModifiedData { get; private set; }

    public CommWindowListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;

        if (_raw.Length >= PlayerCountOffset + 4)
        {
            _playerCount = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
                _raw.AsSpan(PlayerCountOffset, 4));
        }
    }

    public void Build()
    {
        if (_playerCount == 0) return;

        // A count that big is the count field being read from the wrong place.
        if (_playerCount > MaxPlausibleCount)
            throw new PacketLayoutException(
                $"player count {_playerCount} at offset {PlayerCountOffset} is not plausible (max {MaxPlausibleCount})",
                PlayerCountOffset);

        // The entries have to fit in the packet; if they don't, the entry size
        // is wrong.
        var entriesEnd = FirstEntryOffset + (long)_playerCount * EntrySize;
        if (entriesEnd > _raw.Length)
            throw new PacketLayoutException(
                $"{_playerCount} entries of {EntrySize} bytes from offset {FirstEntryOffset} need {entriesEnd} bytes, " +
                $"but the packet is {_raw.Length}; the entry size has probably changed",
                FirstEntryOffset);

        var dict = _deps.M00Dict("local_player_names");
        var buf = (byte[])_raw.Clone();
        var changed = false;
        var namesFound = 0;
        var slotsNotText = 0;

        for (var i = 0; i < _playerCount; i++)
        {
            var nameOff = FirstEntryOffset + (i * EntrySize) + NamePositionInEntry;
            if (nameOff + NameBufferSize > buf.Length) break;

            // The name's 19-byte slot. If what is in it isn't text it isn't a
            // name (the entries aren't where we think they are, or this is some
            // other field), so don't write over it.
            if (!PacketText.TryReadSlot(buf.AsSpan(nameOff, NameBufferSize), out var jpName))
            {
                slotsNotText++;
                continue;
            }
            if (jpName.Length == 0) continue;
            namesFound++;

            var translated = dict.TryGetValue(jpName, out var en) && !string.IsNullOrEmpty(en)
                ? en
                : _deps.Romanizer.ToRomaji(jpName, MaxNameLength);

            // \x04 occupies one of the MaxNameLength slots, so cap the name itself at MaxNameLength - 1.
            if (translated.Length > MaxNameLength - 1) translated = translated[..(MaxNameLength - 1)];

            var nameBytes = Encoding.UTF8.GetBytes(translated);
            // \x04 prefix suppresses the GM-face icon; prepend it before the name.
            var enBytes = new byte[1 + nameBytes.Length];
            enBytes[0] = 0x04;
            nameBytes.CopyTo(enBytes, 1);
            if (enBytes.Length > NameBufferSize) enBytes = enBytes[..NameBufferSize];

            // overwrite name slot with translated + null padding
            for (var b = 0; b < NameBufferSize; b++)
                buf[nameOff + b] = b < enBytes.Length ? enBytes[b] : (byte)0;

            changed = true;
        }

        // Every slot that held anything held non-text: the entry layout has
        // moved. Nothing was rewritten, so leave the packet alone and report.
        if (namesFound == 0 && slotsNotText > 0)
            throw new PacketLayoutException(
                $"none of the {slotsNotText} non-empty name slots (first at offset {FirstEntryOffset + NamePositionInEntry}, " +
                $"every {EntrySize} bytes) hold text; the entry layout has probably changed");

        if (changed) ModifiedData = buf;
    }
}
