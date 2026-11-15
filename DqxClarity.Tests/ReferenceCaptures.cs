using System.Buffers.Binary;
using DqxClarity.Packets;

namespace DqxClarity.Tests;

// Finds and loads the captured packets in docs/packets/references.
//
// Each capture is a binary file with no extension (the matching .txt is its
// hex dump). Most hold a whole network packet -- the size header, then
// opcode + marker + data -- and some hold just opcode + marker + data. Load()
// handles both and returns what a packet class receives: the data after the
// opcode and marker.
//
// Files with "modified" in the name are saved OUTPUTS (e.g. the bad bytes that
// crashed the game in an old bug), not packets the server sends, so they are
// left out.
public static class ReferenceCaptures
{
    public sealed record Capture(string Name, byte OpCode, ushort Marker, byte[] Data)
    {
        public string PacketName => DataPacketRouter.GetPacketName(OpCode, Marker, Data);
        public override string ToString() => Name;
    }

    public static string Directory { get; } = FindReferenceDirectory();

    // xUnit [MemberData] source: one row per capture file, by relative path.
    public static IEnumerable<object[]> All() =>
        System.IO.Directory.EnumerateFiles(Directory, "*", SearchOption.AllDirectories)
            .Where(p => Path.GetExtension(p).Length == 0)
            .Where(p => !Path.GetFileName(p).Contains("modified", StringComparison.OrdinalIgnoreCase))
            .Select(p => Path.GetRelativePath(Directory, p).Replace('\\', '/'))
            .OrderBy(p => p, StringComparer.Ordinal)
            .Select(p => new object[] { p });

    public static Capture Load(string relativePath)
    {
        var bytes = File.ReadAllBytes(Path.Combine(Directory, relativePath));

        // Prefer the reading that lands on a packet type the router knows.
        var framed = TryFramed(relativePath, bytes);
        if (framed != null && IsKnown(framed)) return framed;

        var bare = TryBare(relativePath, bytes);
        if (bare != null && IsKnown(bare)) return bare;

        return framed ?? bare
            ?? throw new InvalidDataException($"{relativePath}: too short to hold a packet ({bytes.Length} bytes)");
    }

    private static bool IsKnown(Capture c) => !c.PacketName.StartsWith("0x", StringComparison.Ordinal);

    // Whole network packet: first byte = (type << 4) | size_id, then the size,
    // then opcode + marker + data. Same rules as GamePacket. Anything after the
    // packet (the rest of the receive buffer) is ignored.
    private static Capture? TryFramed(string name, byte[] b)
    {
        if (b.Length < 2 || (b[0] >> 4) != 0) return null;

        int size, start;
        switch (b[0] & 0x0F)
        {
            case 0: size = b[1]; start = 2; break;
            case 1:
                if (b.Length < 3) return null;
                size = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(1, 2)); start = 3; break;
            case 2:
            case 3:
                if (b.Length < 5) return null;
                size = (int)BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(1, 4)); start = 5; break;
            default: return null;
        }
        if (size < 3 || start + size > b.Length) return null;

        var payload = b.AsSpan(start, size);
        return new Capture(name, payload[0], (ushort)((payload[1] << 8) | payload[2]), payload[3..].ToArray());
    }

    // Just opcode + marker + data.
    private static Capture? TryBare(string name, byte[] b) =>
        b.Length < 3 ? null : new Capture(name, b[0], (ushort)((b[1] << 8) | b[2]), b[3..]);

    private static string FindReferenceDirectory()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "docs", "packets", "references");
            if (System.IO.Directory.Exists(candidate)) return candidate;
        }
        throw new DirectoryNotFoundException(
            "docs/packets/references not found above " + AppContext.BaseDirectory);
    }
}
