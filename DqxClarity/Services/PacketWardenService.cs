using DqxClarity.Hooking;

namespace DqxClarity.Services;

// Manages PacketWarden.dll inside DQXGame.exe.
//
// Owns the named-pipe server (PacketPipe). Delegates the actual dll injection
// to LocaleEmulatorService.InjectWithRetry which already has the working
// K32EnumProcessModulesEx-based wow64 module enumeration — the homegrown
// CreateToolhelp32Snapshot variant that used to live here returned 0 silently
// when called against a wow64 target from an x64 host.
internal sealed class PacketWardenService : IDisposable
{
    private readonly PacketPipe _pipe;

    public PacketWardenService(PacketPipe.PacketHandler handler)
    {
        _pipe = new PacketPipe(handler);
    }

    public void StartPipe() => _pipe.Start();
    public void StopPipe() => _pipe.Stop();
    public void Dispose() => _pipe.Dispose();

    private static string NativeDir()
    {
        var exe = Environment.ProcessPath ?? AppContext.BaseDirectory;
        return Path.Combine(Path.GetDirectoryName(exe) ?? AppContext.BaseDirectory, "misc_files");
    }

    public static void EnsureExtracted()
    {
        using var stream = typeof(PacketWardenService).Assembly.GetManifestResourceStream("PacketWarden.dll");
        if (stream == null) return;
        Directory.CreateDirectory(NativeDir());
        using var fs = File.Create(Path.Combine(NativeDir(), "PacketWarden.dll"));
        stream.CopyTo(fs);
    }

    public static bool IsAvailable() =>
        File.Exists(Path.Combine(NativeDir(), "PacketWarden.dll"));

    public static bool InjectInto(IntPtr hProcess, Action<string>? log = null)
    {
        var dllPath = Path.Combine(NativeDir(), "PacketWarden.dll");
        if (!File.Exists(dllPath))
        {
            log?.Invoke("PacketWarden.dll not found at that path. EnsureExtracted likely didn't run, or the published bundle is missing it.");
            return false;
        }

        // Quick architecture sanity check on the dll bits so we don't waste retries
        // when the dll isn't a 32-bit pe.
        try
        {
            using var fs = File.OpenRead(dllPath);
            var hdr = new byte[0x40];
            fs.ReadExactly(hdr);
            var peOff = BitConverter.ToInt32(hdr, 0x3C);
            fs.Seek(peOff, SeekOrigin.Begin);
            var pe = new byte[6];
            fs.ReadExactly(pe);
            var machine = BitConverter.ToUInt16(pe, 4);
            if (machine != 0x014c)
            {
                log?.Invoke("aborting: PacketWarden.dll must be 32-bit to inject into DQXGame.exe.");
                return false;
            }
        }
        catch (Exception ex) { log?.Invoke($"could not read dll header: {ex.Message}"); }

        return LocaleEmulatorService.InjectWithRetry(hProcess, dllPath, log);
    }
}
