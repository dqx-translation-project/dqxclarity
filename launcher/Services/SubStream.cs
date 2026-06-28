namespace DqxClarity.Launcher.Services;

/// <summary>
/// A read-only, seekable view over a window [start, start+length) of an underlying seekable
/// stream, presented to callers as positions 0..length.
///
/// This exists because a ZIP's End-Of-Central-Directory record lives at the END of the data and
/// its internal offsets are absolute from the START of the zip data. You therefore cannot simply
/// hand <see cref="System.IO.Compression.ZipArchive"/> a CLPK FileStream that has been seeked past
/// the header — the offsets would be wrong. Wrapping the payload byte range in a SubStream makes the
/// zip payload look like a standalone zip starting at position 0, so ZipArchive reads it correctly.
/// </summary>
public sealed class SubStream : Stream
{
    private readonly Stream _inner;
    private readonly long _start;
    private readonly long _length;
    private readonly bool _leaveOpen;
    private long _position;

    public SubStream(Stream inner, long start, long length, bool leaveOpen)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        if (!inner.CanRead || !inner.CanSeek)
            throw new ArgumentException("Underlying stream must be readable and seekable.", nameof(inner));
        if (start < 0) throw new ArgumentOutOfRangeException(nameof(start));
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));

        _inner = inner;
        _start = start;
        _length = length;
        _leaveOpen = leaveOpen;
        _position = 0;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set
        {
            if (value < 0) throw new ArgumentOutOfRangeException(nameof(value));
            _position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (offset < 0 || count < 0 || offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(count));

        if (_position >= _length) return 0;

        var remaining = _length - _position;
        if (count > remaining) count = (int)remaining;
        if (count <= 0) return 0;

        // Position the underlying stream every read — the SubStream owns its own logical cursor and
        // must not assume the inner stream's position is where we last left it.
        _inner.Position = _start + _position;
        var read = _inner.Read(buffer, offset, count);
        _position += read;
        return read;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        var target = origin switch
        {
            SeekOrigin.Begin   => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End     => _length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (target < 0) throw new IOException("Cannot seek before the start of the stream.");
        _position = target;
        return _position;
    }

    public override void Flush() { }

    public override void SetLength(long value) =>
        throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_leaveOpen)
            _inner.Dispose();
        base.Dispose(disposing);
    }
}
