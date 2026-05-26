using System.Buffers.Binary;

namespace DqxClarity.Packets;

// First byte of an inbound packet encodes (type << 4) | size_id.
//   type 0 = data    -> upper nibble 0, lower nibble selects size_id 0..3
//   type 1 = ping
//   type 2 = pong
//   type 3 = ackn
//
// For data packets, size_id chooses the size-width and payload offset:
//   0: 1-byte size, payload at +2
//   1: 2-byte size, payload at +3
//   2: 4-byte size, payload at +5
//   3: 4-byte size, payload at +5
//
// OriginalSize is what we tell the game we consumed, even if we substitute a
// longer/shorter packet — that preserves the caller's stream position.
public sealed class GamePacket
{
    private readonly byte[] _raw;
    private byte[]? _modifiedData;
    private uint? _originalSize;
    private int? _modifiedPacketSize;

    public GamePacket(byte[] raw)
    {
        _raw = raw;
    }

    public byte[]? ModifiedData => _modifiedData;
    public uint? OriginalSize => _originalSize;
    // Size of just-the-packet inside ModifiedData (new header + modified payload),
    // excluding the trailing stream-remainder bytes. Used by debug logging so the
    // hex dump matches exactly what this packet contributes.
    public int? ModifiedPacketSize => _modifiedPacketSize;

    public string PacketKind { get; private set; } = "";

    // Parse + optionally produce ModifiedData via the router.
    public void Parse(DataPacketRouter.Dispatcher dispatcher)
    {
        if (_raw.Length == 0) return;

        var first = _raw[0];
        var type = first >> 4;
        switch (type)
        {
            case 0:
                PacketKind = "data";
                ParseData(dispatcher);
                break;
            case 1: PacketKind = "ping"; break;
            case 2: PacketKind = "pong"; break;
            case 3: PacketKind = "ackn"; break;
        }
    }

    private void ParseData(DataPacketRouter.Dispatcher dispatcher)
    {
        var sizeId = _raw[0] & 0x0F;
        int size;
        int payloadStart;

        switch (sizeId)
        {
            case 0:
                if (_raw.Length < 2) return;
                size = _raw[1];
                _originalSize = (uint)(size + 2);
                payloadStart = 2;
                break;
            case 1:
                if (_raw.Length < 3) return;
                size = BinaryPrimitives.ReadUInt16LittleEndian(_raw.AsSpan(1, 2));
                _originalSize = (uint)(size + 3);
                payloadStart = 3;
                break;
            case 2:
            case 3:
                if (_raw.Length < 5) return;
                size = (int)BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(1, 4));
                _originalSize = (uint)(size + 4);
                payloadStart = 5;
                break;
            default:
                return;
        }

        if (payloadStart + size > _raw.Length) return;

        var payload = _raw.AsSpan(payloadStart, size).ToArray();
        var remainder = _raw.AsSpan(payloadStart + size).ToArray();

        if (size != payload.Length) return;

        var router = new DataPacketRouter(payload);
        router.Parse(dispatcher);

        if (router.ModifiedData != null && router.ModifiedSize > 0)
        {
            var header = RecalculateSize(router.ModifiedSize);
            var total = new byte[header.Length + router.ModifiedData.Length + remainder.Length];
            Buffer.BlockCopy(header, 0, total, 0, header.Length);
            Buffer.BlockCopy(router.ModifiedData, 0, total, header.Length, router.ModifiedData.Length);
            Buffer.BlockCopy(remainder, 0, total, header.Length + router.ModifiedData.Length, remainder.Length);
            _modifiedData = total;
            _modifiedPacketSize = header.Length + router.ModifiedData.Length;
        }
    }

    private static int RemainderTrailLength(int rawLen, int payloadStart, int size)
    {
        var rem = rawLen - payloadStart - size;
        return rem < 0 ? 0 : rem;
    }

    // Picks the smallest size_id that fits the payload size.
    private static byte[] RecalculateSize(int size)
    {
        if (size <= 0xFF)
            return new byte[] { 0x00, (byte)size };
        if (size <= 0xFFFF)
        {
            var b = new byte[3];
            b[0] = 0x01;
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(1), (ushort)size);
            return b;
        }
        if (size <= 0xFFFFFF)
        {
            var b = new byte[5];
            b[0] = 0x02;
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(1), (uint)size);
            return b;
        }
        else
        {
            var b = new byte[5];
            b[0] = 0x03;
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(1), (uint)size);
            return b;
        }
    }
}
