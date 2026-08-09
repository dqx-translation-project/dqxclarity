using System.Buffers.Binary;
using System.Text;

namespace DqxClarity.Packets;

// All integer reads are little-endian; cstrings are utf-8 with a trailing null byte.
public ref struct PacketReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _pos;

    public PacketReader(ReadOnlySpan<byte> data)
    {
        _data = data;
        _pos = 0;
    }

    public int Position => _pos;
    public int Length => _data.Length;
    public int Remaining => _data.Length - _pos;
    public bool AtEnd => _pos >= _data.Length;

    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        var slice = _data.Slice(_pos, count);
        _pos += count;
        return slice;
    }

    public byte ReadU8()
    {
        var v = _data[_pos];
        _pos += 1;
        return v;
    }

    public ushort ReadU16()
    {
        var v = BinaryPrimitives.ReadUInt16LittleEndian(_data.Slice(_pos, 2));
        _pos += 2;
        return v;
    }

    public uint ReadU32()
    {
        var v = BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_pos, 4));
        _pos += 4;
        return v;
    }

    public ulong ReadU64()
    {
        var v = BinaryPrimitives.ReadUInt64LittleEndian(_data.Slice(_pos, 8));
        _pos += 8;
        return v;
    }

    // Reads up to (but not including) the next 0x00, then skips past it.
    // If no null terminator is found, reads to end of buffer.
    public string ReadCString(Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;
        var rest = _data[_pos..];
        var nullIdx = rest.IndexOf((byte)0);
        if (nullIdx < 0)
        {
            var all = encoding.GetString(rest);
            _pos = _data.Length;
            return all;
        }
        var str = encoding.GetString(rest[..nullIdx]);
        _pos += nullIdx + 1;
        return str;
    }

    public void Seek(int pos) => _pos = pos;
    public void Skip(int count) => _pos += count;

    public ReadOnlySpan<byte> RemainingBytes() => _data[_pos..];
}

public sealed class PacketWriter
{
    private readonly List<byte> _data = new();

    public int Length => _data.Count;

    public void WriteBytes(ReadOnlySpan<byte> bytes)
    {
        foreach (var b in bytes) _data.Add(b);
    }

    public void WriteU8(byte value) => _data.Add(value);

    public void WriteU16(ushort value)
    {
        Span<byte> buf = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(buf, value);
        WriteBytes(buf);
    }

    public void WriteU32(uint value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, value);
        WriteBytes(buf);
    }

    public void WriteU64(ulong value)
    {
        Span<byte> buf = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(buf, value);
        WriteBytes(buf);
    }

    public void WriteCString(string value, Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;
        WriteBytes(encoding.GetBytes(value));
        _data.Add(0);
    }

    public byte[] Build() => _data.ToArray();
}
