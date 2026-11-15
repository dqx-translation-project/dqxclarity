using System.Text;

namespace DqxClarity.Packets;

// Builds a modified copy of a packet by replacing specific byte ranges and
// copying everything else through exactly as it arrived. Packet classes that
// only rewrite a few strings use it so that fields they don't translate --
// and every byte they don't understand -- can't be changed by accident.
//
//   var patch = new PacketPatch(raw);
//   patch.ReplaceText(nameStart, nameLength, "Shoubu");   // the null after it is kept
//   if (patch.HasEdits) ModifiedData = patch.Build();
public sealed class PacketPatch
{
    private readonly byte[] _raw;
    private readonly List<(int Start, int Length, byte[] Bytes)> _edits = new();

    public PacketPatch(byte[] raw) => _raw = raw;

    public bool HasEdits => _edits.Count > 0;

    // Replaces raw[start .. start+length) with `bytes`. Ranges must not overlap.
    public void Replace(int start, int length, byte[] bytes)
    {
        if (start < 0 || length < 0 || start + length > _raw.Length)
            throw new ArgumentOutOfRangeException(nameof(start), $"range {start}+{length} is outside the {_raw.Length}-byte packet");
        _edits.Add((start, length, bytes));
    }

    public void ReplaceText(int start, int length, string text) =>
        Replace(start, length, Encoding.UTF8.GetBytes(text));

    public byte[] Build()
    {
        var writer = new PacketWriter();
        var pos = 0;
        foreach (var (start, length, bytes) in _edits.OrderBy(e => e.Start))
        {
            if (start < pos)
                throw new InvalidOperationException($"overlapping edits at offset {start}");
            writer.WriteBytes(_raw.AsSpan(pos, start - pos));
            writer.WriteBytes(bytes);
            pos = start + length;
        }
        writer.WriteBytes(_raw.AsSpan(pos));
        return writer.Build();
    }

    // Cuts utf-8 bytes to at most `max` without splitting a multi-byte character.
    public static byte[] TruncateUtf8Bytes(byte[] bytes, int max)
    {
        if (bytes.Length <= max) return bytes;
        var cut = Math.Max(0, max);
        while (cut > 0 && (bytes[cut] & 0xC0) == 0x80) cut--;
        return bytes[..cut];
    }

    // Cuts a string to at most `maxBytes` of utf-8 without splitting a character.
    public static string TruncateUtf8(string s, int maxBytes)
    {
        if (Encoding.UTF8.GetByteCount(s) <= maxBytes) return s;
        var sb = new StringBuilder();
        var running = 0;
        foreach (var rune in s.EnumerateRunes())
        {
            var len = rune.Utf8SequenceLength;
            if (running + len > maxBytes) break;
            sb.Append(rune.ToString());
            running += len;
        }
        return sb.ToString();
    }
}
