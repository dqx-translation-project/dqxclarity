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

    // ---- Strict reads ---------------------------------------------------
    // For packets whose layout can change between game updates. Where the
    // plain reads above quietly hand back whatever bytes are there, these
    // throw PacketLayoutException when the data isn't shaped the way the
    // caller said it is. PacketGuard turns that into "leave the packet alone
    // and save a mismatch report" -- see PacketLayoutException. `what` names
    // the field for the report ("entity name", "quest title", ...).

    public ReadOnlySpan<byte> ReadBytesStrict(int count, string what)
    {
        if (count < 0 || count > Remaining)
            throw new PacketLayoutException($"{what}: needs {count} bytes at offset {_pos}, only {Remaining} left", _pos);
        return ReadBytes(count);
    }

    // Null-terminated utf-8 text. The terminator must exist within maxBytes
    // and everything before it must be text (line breaks allowed).
    public string ReadCStringStrict(string what, int maxBytes = 1024)
    {
        var start = _pos;
        var rest = _data[_pos..];
        var nul = rest.IndexOf((byte)0);
        if (nul < 0)
            throw new PacketLayoutException($"{what}: no null terminator after offset {start}", start);
        if (nul > maxBytes)
            throw new PacketLayoutException($"{what}: string at offset {start} is {nul} bytes, more than the {maxBytes} allowed", start);
        if (!PacketText.TryDecode(rest[..nul], out var text, allowLineBreaks: true))
            throw new PacketLayoutException($"{what}: the {nul} bytes at offset {start} are not valid text", start);

        _pos += nul + 1;
        return text;
    }

    // u32 byte length (including the null) followed by that many bytes of
    // text ending in a single null -- the usual shape for text fields. The
    // length has to fit in what is left, end exactly on the null, and the
    // text in between has to be text.
    public string ReadLengthPrefixedCStringStrict(string what, int maxBytes = 65536)
    {
        var start = _pos;
        if (Remaining < 4)
            throw new PacketLayoutException($"{what}: no room for a length field at offset {start}", start);

        var length = BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_pos, 4));
        if (length < 1 || length > (uint)maxBytes || length > (uint)(Remaining - 4))
            throw new PacketLayoutException($"{what}: length field at offset {start} says {length} bytes, with {Remaining - 4} left", start);

        var body = _data.Slice(_pos + 4, (int)length);
        if (body[body.Length - 1] != 0)
            throw new PacketLayoutException($"{what}: the {length}-byte string at offset {start + 4} does not end in a null", start);

        var textBytes = body[..(body.Length - 1)];
        if (textBytes.IndexOf((byte)0) >= 0)
            throw new PacketLayoutException($"{what}: the string at offset {start + 4} has a null before its stated end", start);
        if (!PacketText.TryDecode(textBytes, out var text, allowLineBreaks: true))
            throw new PacketLayoutException($"{what}: the string at offset {start + 4} is not valid text", start);

        _pos += 4 + (int)length;
        return text;
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
