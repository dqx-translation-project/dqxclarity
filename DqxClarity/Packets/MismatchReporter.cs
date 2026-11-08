using System.Text;
using System.Text.RegularExpressions;

namespace DqxClarity.Packets;

// Saves a report whenever a packet class can't make sense of the bytes it was
// given (a PacketLayoutException) or fails outright (any other exception),
// so a game update that changes a packet shows up as a file that can be sent
// in and fixed, instead of as a feature that quietly stops working.
//
// Each report is two files in <exe dir>/logs/packet_mismatches/:
//   <time>_<op>-<marker>_<name>.txt  readable: what failed, where the text
//                                    actually sits in the data (compare with
//                                    the offsets in the packet class), and a
//                                    full hex dump of the data
//   <time>_<op>-<marker>_<name>.bin  opcode + marker + data, the same format
//                                    as the files in docs/packets/references,
//                                    so it can be dropped in as a sample
//
// One report per distinct problem per session (the key is the packet, the
// exception type and the message with its numbers stripped), and at most
// MaxReportsPerSession in all, so a packet that fails on every single
// arrival can't fill the disk. A one-line summary with the file name also goes
// to the launcher log. Reporting never throws.
public sealed class MismatchReporter
{
    private const int MaxReportsPerSession = 30;

    private readonly string _reportDirectory;
    private readonly HashSet<string> _seen = new();
    private readonly object _gate = new();
    private int _written;
    private bool _announcedCap;

    // Launcher log sink: (message, isError). Set after construction.
    public Action<string, bool>? Log { get; set; }

    public MismatchReporter(string reportDirectory)
    {
        _reportDirectory = reportDirectory;
    }

    public void Report(byte opCode, ushort marker, byte[] data, Exception ex)
    {
        try
        {
            var key = $"{opCode:X2}{marker:X4}|{ex.GetType().Name}|{Regex.Replace(ex.Message, @"\d+", "#")}";
            lock (_gate)
            {
                if (!_seen.Add(key)) return;
                if (_written >= MaxReportsPerSession)
                {
                    if (!_announcedCap)
                    {
                        _announcedCap = true;
                        Log?.Invoke($"[layout] more than {MaxReportsPerSession} packet mismatch reports this session; no more will be saved", true);
                    }
                    return;
                }
                _written++;
            }

            var name = DataPacketRouter.GetPacketName(opCode, marker, data);
            var category = ex switch
            {
                PacketLayoutException => "layout does not match",
                ArgumentException or IndexOutOfRangeException => "read past the end of the data",
                _ => "unexpected error",
            };

            var strings = LayoutDiagnostics.FindStrings(data);

            var sb = new StringBuilder();
            sb.Append("dqxclarity packet mismatch report\n");
            sb.Append($"time      : {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n");
            sb.Append($"packet    : {name} (opcode 0x{opCode:X2}, marker 0x{marker:X4})\n");
            sb.Append($"kind      : {category}\n");
            sb.Append($"problem   : {ex.Message}\n");
            if (ex is PacketLayoutException { Offset: { } at })
                sb.Append($"at offset : {at} (0x{at:X})\n");
            sb.Append($"data      : {data.Length} bytes. All offsets in this report are into the data, i.e. just\n");
            sb.Append("            after the opcode + marker, which is what the packet classes use.\n");

            var stack = (ex.StackTrace ?? "").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).Take(3);
            sb.Append($"raised in : {string.Join(" <- ", stack)}\n");

            sb.Append("\nJapanese text found in the data, and where it actually sits:\n");
            if (strings.Count == 0)
                sb.Append("  (none found)\n");
            foreach (var s in strings)
                sb.Append($"  {(s.LengthPrefixed ? "length-prefixed" : "null-terminated")}  offset {s.Offset} (0x{s.Offset:X}): \"{s.Text}\"\n");

            var stride = LayoutDiagnostics.StrideHint(strings);
            if (stride != null)
                sb.Append($"  hint: {stride}\n");

            sb.Append("\nHex dump of the data:\n");
            sb.Append(LayoutDiagnostics.HexDump(data));

            var safeName = Regex.Replace(name, @"[^A-Za-z0-9]+", "_").Trim('_');
            var baseName = $"{DateTime.Now:yyyyMMdd-HHmmss}_{opCode:X2}-{marker:X4}_{safeName}";
            Directory.CreateDirectory(_reportDirectory);

            var textPath = Path.Combine(_reportDirectory, baseName + ".txt");
            File.WriteAllText(textPath, sb.ToString(), new UTF8Encoding(false));

            var bin = new byte[3 + data.Length];
            bin[0] = opCode;
            bin[1] = (byte)(marker >> 8);
            bin[2] = (byte)(marker & 0xFF);
            Buffer.BlockCopy(data, 0, bin, 3, data.Length);
            File.WriteAllBytes(Path.Combine(_reportDirectory, baseName + ".bin"), bin);

            Log?.Invoke($"[layout] {name}: {ex.Message} -- left untouched; report saved as logs/packet_mismatches/{baseName}.txt", true);
        }
        catch
        {
            // Reporting must never get in the way of packet handling.
        }
    }
}
