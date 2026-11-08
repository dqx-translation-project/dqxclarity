using System.Buffers.Binary;
using System.Text;

namespace DqxClarity.Packets;

public readonly record struct FoundString(int Offset, string Text, bool LengthPrefixed);

// Works out where the text in a packet actually sits, independent of what any
// packet class believes. Used by MismatchReporter so a report says, in effect,
// "the class looked for the name at 575 but there is a Japanese string at 605"
// -- which is most of the work of fixing a layout change.
public static class LayoutDiagnostics
{
    // Finds Japanese text in the data, as either
    //   - a u32 length (including the null) + text + null, or
    //   - a bare null-terminated string.
    // Offsets are into data, the same offsets the packet classes use.
    public static List<FoundString> FindStrings(byte[] data, int limit = 60)
    {
        var found = new List<FoundString>();
        var covered = new bool[data.Length];

        // 1. length-prefixed
        for (var o = 0; o + 6 <= data.Length && found.Count < limit; o++)
        {
            var length = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(o, 4));
            if (length < 2 || length > 512 || o + 4 + length > data.Length) continue;

            var body = data.AsSpan(o + 4, (int)length);
            if (body[^1] != 0) continue;

            var text = body[..^1];
            if (text.IndexOf((byte)0) >= 0) continue;
            if (!PacketText.TryDecode(text, out var s, true) || !PacketText.HasJapanese(s)) continue;

            found.Add(new FoundString(o, s, true));
            for (var k = o; k < o + 4 + (int)length; k++) covered[k] = true;
            o += 4 + (int)length - 1;
        }

        // 2. bare null-terminated, from runs of non-zero bytes not already claimed
        var i = 0;
        while (i < data.Length && found.Count < limit)
        {
            if (data[i] == 0 || covered[i]) { i++; continue; }

            var end = i;
            while (end < data.Length && data[end] != 0 && !covered[end]) end++;

            if (end - i >= 6 && end - i <= 400)
            {
                // The text may be preceded by non-text bytes in the same run
                // (a flag byte, say), so try each plausible starting point.
                for (var start = i; start + 6 <= end; start++)
                {
                    if ((data[start] & 0xC0) == 0x80) continue; // utf-8 continuation byte
                    if (PacketText.TryDecode(data.AsSpan(start, end - start), out var s, true) && PacketText.HasJapanese(s))
                    {
                        found.Add(new FoundString(start, s, false));
                        break;
                    }
                }
            }

            i = end + 1;
        }

        found.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        return found;
    }

    // For list-shaped packets: if most consecutive strings are the same
    // distance apart, that distance is probably the record stride.
    public static string? StrideHint(IReadOnlyList<FoundString> strings)
    {
        if (strings.Count < 3) return null;

        var gaps = new Dictionary<int, int>();
        for (var k = 1; k < strings.Count; k++)
        {
            var gap = strings[k].Offset - strings[k - 1].Offset;
            gaps[gap] = gaps.GetValueOrDefault(gap) + 1;
        }

        var best = gaps.OrderByDescending(g => g.Value).First();
        if (best.Value < 2) return null;
        return $"{best.Value} of {strings.Count - 1} gaps between consecutive strings are {best.Key} bytes (0x{best.Key:X}) -- possibly a record stride";
    }

    // Same layout as the debug view's dump: offset, 16 bytes with a gap at 8, ascii.
    public static string HexDump(byte[] data)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < data.Length; i += 16)
        {
            sb.Append($"  {i:X8}  ");
            var count = Math.Min(16, data.Length - i);
            for (var j = 0; j < 16; j++)
            {
                if (j == 8) sb.Append(' ');
                if (j < count) sb.Append($"{data[i + j]:X2} ");
                else sb.Append("   ");
            }
            sb.Append(" |");
            for (var j = 0; j < count; j++)
            {
                var b = data[i + j];
                sb.Append(b is >= 0x20 and <= 0x7E ? (char)b : '.');
            }
            sb.Append('|').Append('\n');
        }
        return sb.ToString();
    }
}
