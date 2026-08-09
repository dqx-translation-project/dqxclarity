using System.Diagnostics;
using System.Runtime.InteropServices;
using DqxClarity.Data;
using DqxClarity.Packets;
using DqxClarity.Services;
using DqxClarity.Translation;

namespace DqxClarity.Hooking;

// Top-of-stack object that owns the entire in-process translation runtime: the
// sqlite db, the translator + backend, the packet router/dispatcher, and the
// hook service that talks to PacketWarden.dll over the named pipe.
//
// Lifetime contract: construct before launching the game, call Start() to bring
// up the pipe server, then InjectInto(hProcess) once the game process exists.
// Dispose tears down the pipe.
public sealed class ClarityRuntime : IDisposable
{
    private readonly ClarityDb _db;
    private readonly Translator _translator;
    private readonly DataPacketRouter.Dispatcher _dispatcher;
    private readonly PacketWardenService _hook;
    private NativeLogTail? _logTail;
    private readonly bool _debugLogging;
    private Action<string, bool>? _log;
    private Action<string, int, string, int, string?>? _debugPacket;

    public ClarityRuntime(ITranslationBackend backend, bool debugLogging = false)
    {
        _debugLogging = debugLogging;
        _db = new ClarityDb(ClarityDb.DefaultDbPath());
        _db.CreateSchema();

        var glossary = GlossaryCache.Load(_db);
        _translator = new Translator(backend, glossary);

        // Surface backend errors (bad api key, rate-limit, scrape regression,
        // etc.) to the user log so they don't silently fall back to "leave the
        // japanese on screen". _log is set later by StartWatchingForGame; the
        // closure reads it at invocation time, so wiring this here is safe.
        backend.OnError = msg => _log?.Invoke("[translate] " + msg, true);

        var deps = new PacketDependencies
        {
            Db = _db,
            Translator = _translator,
            Romanizer = new WanaKanaRomanizer(),  // p/invokes wanakana.dll; falls back to passthrough if missing
        };
        _dispatcher = DataPacketRouter.BuildDefaultDispatcher(deps);

        _hook = new PacketWardenService(HandlePacket);
    }

    public void SetDebugCallback(Action<string, int, string, int, string?> callback) => _debugPacket = callback;

    public void Start()
    {
        PacketWardenService.EnsureExtracted();
        _hook.StartPipe();
    }

    public bool InjectInto(IntPtr hProcess) => PacketWardenService.InjectInto(hProcess);

    // Fired by the watcher loop when the previously-injected DQXGame.exe pid
    // disappears. Owners (MainViewModel) hook this to run the same teardown
    // sequence as the user-initiated Stop button.
    public event Action? GameExited;

    public void Stop()
    {
        _watchCts?.Cancel();
        _logTail?.Stop();
        _hook.StopPipe();
    }

    public void Dispose()
    {
        _watchCts?.Cancel();
        _logTail?.Dispose();
        _hook.Dispose();
    }

    // Background watcher: polls for DQXGame.exe. On finding a new pid we haven't injected
    // into yet, opens the process with full rights, calls InjectInto, and
    // updates _lastInjectedPid so a fresh game launch retriggers injection.
    private CancellationTokenSource? _watchCts;
    private int _lastInjectedPid;

    public void StartWatchingForGame(Action<string, bool> log)
    {
        _log = log;
        _watchCts?.Cancel();
        _watchCts = new CancellationTokenSource();
        var ct = _watchCts.Token;
        Task.Run(async () => await WatchLoop(log, ct), ct);

        // Start tailing the native dll's log file so its progress (signature
        // scan, hook install, pipe connect, parser errors) appears in the c#
        // log view too. Path mirrors what PacketWarden.cpp Log() writes to:
        // <exe-dir>/logs/packetwarden.log.
        var exe = Environment.ProcessPath ?? AppContext.BaseDirectory;
        var dir = Path.GetDirectoryName(exe) ?? AppContext.BaseDirectory;
        var nativeLog = Path.Combine(dir, "logs", "packetwarden.log");
        _logTail = new NativeLogTail(nativeLog, line =>
            log("[hook] " + StripTimestamp(line), false));
        _logTail.Start();
    }

    // The native dll prefixes each line with "YYYY-MM-DD HH:MM:SS ". Strip it
    // since the c# log view already shows timestamps on its own row.
    private static string StripTimestamp(string line)
    {
        if (line.Length > 20 && line[4] == '-' && line[7] == '-' && line[10] == ' '
            && line[13] == ':' && line[16] == ':' && line[19] == ' ')
            return line[20..];
        return line;
    }

    private async Task WatchLoop(Action<string, bool> log, CancellationToken ct)
    {
        log("Watching for DQXGame.exe…", false);
        while (!ct.IsCancellationRequested)
        {
            Process[] procs = Array.Empty<Process>();
            try
            {
                procs = Process.GetProcessesByName("DQXGame");

                // Game-exit detection: if we previously injected into a pid and
                // it no longer exists, fire GameExited and stop watching. The
                // owner (MainViewModel) will dispose the runtime, which in turn
                // cancels this loop via _watchCts.
                if (_lastInjectedPid != 0 && !procs.Any(p => p.Id == _lastInjectedPid))
                {
                    log($"DQXGame.exe (pid {_lastInjectedPid}) exited; stopping translation runtime.", false);
                    GameExited?.Invoke();
                    return;
                }

                if (procs.Length > 0 && procs[0].Id != _lastInjectedPid)
                {
                    var pid = procs[0].Id;
                    // let the game finish its early loader steps.
                    await Task.Delay(2000, ct).ConfigureAwait(false);

                    var h = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)pid);
                    if (h == IntPtr.Zero)
                    {
                        log($"OpenProcess({pid}) failed (win32 err {Marshal.GetLastWin32Error()}). " +
                            "If dqx is elevated, the launcher needs to be too.", true);
                        await Task.Delay(2000, ct).ConfigureAwait(false);
                    }
                    else
                    {
                        log($"Found DQXGame.exe (pid {pid}); injecting PacketWarden.dll", false);
                        var ok = PacketWardenService.InjectInto(h, msg => log("  " + msg, true));
                        CloseHandle(h);
                        if (ok)
                        {
                            _lastInjectedPid = pid;
                            log("Injected successfully.", false);
                        }
                        else
                        {
                            log("Injection failed; will retry.", true);
                            await Task.Delay(2000, ct).ConfigureAwait(false);
                        }
                    }
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { log($"watch loop error: {ex.Message}", true); }
            finally
            {
                foreach (var p in procs) p.Dispose();
            }

            try { await Task.Delay(500, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    private byte[]? HandlePacket(ReadOnlyMemory<byte> packet)
    {
        try
        {
            var raw = packet.ToArray();
            var gp = new GamePacket(raw);
            gp.Parse(_dispatcher);
            var result = gp.ModifiedData;

            if (_debugLogging && _debugPacket != null)
            {
                // Slice raw + modified down to just-the-packet bytes (no trailing
                // stream remainder) so the debug grid shows exactly what GamePacket
                // considers this packet. For non-data packets where OriginalSize
                // is null (ping/pong/ackn, type 4 in forward-all mode), fall back
                // to the full buffer length.
                var rawSize = gp.OriginalSize.HasValue && gp.OriginalSize.Value <= (uint)raw.Length
                    ? (int)gp.OriginalSize.Value
                    : raw.Length;
                var rawSlice = rawSize == raw.Length ? raw : raw.AsSpan(0, rawSize).ToArray();

                byte[]? modSlice = null;
                int modSize = 0;
                if (result != null)
                {
                    modSize = gp.ModifiedPacketSize.HasValue && gp.ModifiedPacketSize.Value <= result.Length
                        ? gp.ModifiedPacketSize.Value
                        : result.Length;
                    modSlice = modSize == result.Length ? result : result.AsSpan(0, modSize).ToArray();
                }

                var typeName = ExtractPacketTypeName(raw);
                var modifiedHex = modSlice != null ? FormatHexDump(modSlice) : null;
                _debugPacket(typeName, rawSize, FormatHexDump(rawSlice), modSize, modifiedHex);
            }

            return result;
        }
        catch (Exception ex)
        {
            if (_debugLogging && _log != null)
                _log($"[debug] packet handler error: {ex.Message}", true);
            return null;
        }
    }

    private static string ExtractPacketTypeName(byte[] raw)
    {
        if (raw.Length == 0) return "Empty";

        var type = raw[0] >> 4;
        if (type != 0) return type switch
        {
            1 => "Ping",
            2 => "Pong",
            3 => "Ackn",
            _ => $"Type{type}",
        };

        var sizeId = raw[0] & 0x0F;
        int payloadStart = sizeId switch
        {
            0 => 2,
            1 => 3,
            _ => 5,
        };

        if (raw.Length < payloadStart + 3) return "Data (too short)";

        var opCode = raw[payloadStart];
        var marker = (ushort)((raw[payloadStart + 1] << 8) | raw[payloadStart + 2]);
        byte[]? payloadData = raw.Length > payloadStart + 3
            ? raw.AsSpan(payloadStart + 3).ToArray()
            : null;
        return DataPacketRouter.GetPacketName(opCode, marker, payloadData);
    }

    private static string FormatHexDump(byte[] data)
    {
        var sb = new System.Text.StringBuilder();

        for (int i = 0; i < data.Length; i += 16)
        {
            sb.Append($"  {i:X8}  ");

            int count = Math.Min(16, data.Length - i);
            for (int j = 0; j < 16; j++)
            {
                if (j == 8) sb.Append(' ');
                if (j < count)
                    sb.Append($"{data[i + j]:X2} ");
                else
                    sb.Append("   ");
            }

            sb.Append(" |");
            for (int j = 0; j < count; j++)
            {
                var b = data[i + j];
                sb.Append(b is >= 0x20 and <= 0x7E ? (char)b : '.');
            }
            sb.Append('|');

            if (i + 16 < data.Length)
                sb.AppendLine();
        }

        return sb.ToString();
    }
}
