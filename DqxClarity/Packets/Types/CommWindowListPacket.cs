using System.Text;

namespace DqxClarity.Packets.Types;

//

// Communication window (team/party member list). Fixed-offset layout: the player
// count lives at offset 12 (u32); entries start at offset 16, each is 213 bytes
// wide, with the name starting at +108 inside the entry, filling a 19-byte slot
// (+ null terminator = 20 total). Names longer than 11 ascii chars crash the game's
// chat window, so we cap at 11 and pad with nulls.
public sealed class CommWindowListPacket : IPacket
{
    private const int PlayerCountOffset = 12;
    private const int FirstEntryOffset = 16;
    private const int EntrySize = 213;
    private const int NamePositionInEntry = 108;
    private const int NameBufferSize = 19;
    private const int MaxNameLength = 11;

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

        var dict = _deps.M00Dict("local_player_names");
        var buf = (byte[])_raw.Clone();
        var changed = false;

        for (var i = 0; i < _playerCount; i++)
        {
            var nameOff = FirstEntryOffset + (i * EntrySize) + NamePositionInEntry;
            if (nameOff + NameBufferSize > buf.Length) break;

            // find null within the name's 19-byte slot
            var end = nameOff;
            while (end < buf.Length && end < nameOff + NameBufferSize && buf[end] != 0) end++;

            var jpName = Encoding.UTF8.GetString(buf, nameOff, end - nameOff);
            if (jpName.Length == 0) continue;

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

        if (changed) ModifiedData = buf;
    }
}
