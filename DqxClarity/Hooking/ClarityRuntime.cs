using System.Diagnostics;
using System.Runtime.InteropServices;
using DqxClarity.Data;
using DqxClarity.Packets;
using DqxClarity.Services;
using DqxClarity.Translation;
using DqxClarity.Updates;

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
    private readonly PacketDependencies _deps;
    private readonly DataPacketRouter.Dispatcher _dispatcher;
    private readonly PacketWardenService _hook;
    private NativeLogTail? _logTail;
    private readonly bool _debugLogging;
    private Action<string, bool>? _log;
    private Action<string, byte[], string, byte[]?, string?>? _debugPacket;

    public ClarityRuntime(
        ITranslationBackend backend,
        bool debugLogging = false,
        bool translatePlayerNameplates = true,
        bool translateNpcNameplates = true,
        bool translateMonsterNameplates = true)
    {
        _debugLogging = debugLogging;
        _db = new ClarityDb(ClarityDb.DefaultDbPath());
        _db.CreateSchema();

        // Local file + db I/O only (no network), so this runs synchronously here --
        // mirrors main.py calling import_name_overrides() before anything else uses
        // the db, so the glossary loaded right below already reflects the user's
        // current name_overrides.json instead of needing a restart to pick it up.
        _db.ImportNameOverrides();

        var glossary = GlossaryCache.Load(_db);
        _translator = new Translator(backend, glossary);

        // Surface backend errors (bad api key, rate-limit, scrape regression,
        // etc.) to the user log so they don't silently fall back to "leave the
        // japanese on screen". _log is set later by StartWatchingForGame; the
        // closure reads it at invocation time, so wiring this here is safe.
        backend.OnError = msg => _log?.Invoke("[translate] " + msg, true);

        _deps = new PacketDependencies
        {
            Db = _db,
            Translator = _translator,
            Romanizer = new WanaKanaRomanizer(),  // p/invokes wanakana.dll; falls back to passthrough if missing
            TranslatePlayerNameplates = translatePlayerNameplates,
            TranslateNpcNameplates = translateNpcNameplates,
            TranslateMonsterNameplates = translateMonsterNameplates,
        };
        _dispatcher = DataPacketRouter.BuildDefaultDispatcher(_deps);

        _hook = new PacketWardenService(HandlePacket);
    }

    public void SetDebugCallback(Action<string, byte[], string, byte[]?, string?> callback) => _debugPacket = callback;

    // The runtime is constructed once (EnsureNativeRuntime's guard means it's
    // never rebuilt) and stays alive for the rest of the process, so the
    // constructor's translatePlayerNameplates/etc. args only ever reflect
    // whatever the ini said at launcher startup. Settings.Run() saves a fresh
    // config to disk but never touches this already-running instance -- so
    // without this method, toggling a nameplate checkbox and hitting Run
    // would silently do nothing until the whole launcher app was restarted,
    // which is not what "hit Run" should feel like. Called from
    // MainViewModel.OnRunRequested with the live checkbox values every time
    // Run fires, so a toggle takes effect on the very next translated packet
    // -- no restart needed. (DebugLogging and the other constructor-time
    // settings don't get this treatment; only these three were reported as
    // silently not applying and are cheap/safe to patch live since nothing
    // else reads them except EntityPacket.Build().)
    public void UpdateNameplateSettings(bool translatePlayerNameplates, bool translateNpcNameplates, bool translateMonsterNameplates)
    {
        _deps.TranslatePlayerNameplates = translatePlayerNameplates;
        _deps.TranslateNpcNameplates = translateNpcNameplates;
        _deps.TranslateMonsterNameplates = translateMonsterNameplates;
    }

    // Same problem as UpdateNameplateSettings above, for name_overrides.json: this
    // runtime -- and the ImportNameOverrides() call in its constructor -- is built
    // once, up front, before the user has necessarily even opened the Overrides tab.
    // In main, every Run spawns a brand new python process that always re-imports
    // the file fresh; here, without this, the normal "edit overrides, click Save,
    // click Run" flow would silently keep using whatever the db looked like at
    // launcher startup until a full app restart. Called from
    // MainViewModel.OnRunRequested every time Run fires, alongside
    // UpdateNameplateSettings, so freshly-saved overrides take effect on the very
    // next translated packet -- no restart needed.
    public void RefreshNameOverrides()
    {
        _db.ImportNameOverrides();
        _translator.UpdateGlossary(GlossaryCache.Load(_db));

        // The player/MyTown name lookup dict is ALSO cached lazily, separately
        // from the glossary (PacketDependencies._m00Cache, populated the first
        // time PlayerContext resolves the active character) -- and unlike the
        // glossary reload above, re-importing the db does nothing to that
        // cache or to the EnPlayerName/EnSiblingName PlayerContext already
        // resolved. Without these two calls, a character that already
        // activated earlier in this session (the common case -- it happens
        // almost immediately after login, automatically) would keep showing
        // whatever name resolution happened BEFORE this refresh no matter how
        // many times overrides are edited and Run is clicked, until the game
        // process fully exits and the launcher rebuilds the whole runtime
        // from scratch. See PlayerContext.ForceReactivate's doc comment.
        _deps.InvalidateM00Cache();
        _deps.PlayerContext.ForceReactivate(_deps);
    }

    public void Start()
    {
        PacketWardenService.EnsureExtracted();
        _hook.StartPipe();
        _ = UpdateTranslationDataAsync();
    }

    // Refreshes clarity_dialog.db (m00_strings, glossary, fixed_dialog_template, walkthrough,
    // quests, story_so_far_template) from the two upstream translation-data sources —
    // port of update.py's download_custom_files(). Main's python engine ran this
    // synchronously before anything else on every run; here it's fire-and-forget so
    // launcher/game startup isn't blocked on a network round-trip. Safe to race against
    // early gameplay: m00_strings/npc lookups in DataPacketRouter are cached lazily per-key
    // on first use, well after the game has finished booting, and the glossary — the one
    // piece loaded eagerly in this constructor — is explicitly reloaded into the live
    // Translator below so this session doesn't need a restart to pick up fresh data.
    private async Task UpdateTranslationDataAsync()
    {
        try
        {
            await new TranslationUpdater(_db, ClarityDb.DefaultDbPath()).RunAsync().ConfigureAwait(false);

            // TranslationUpdater's custom-zip import (ImportCustomZipAsync) does an
            // unconditional, unscoped "DELETE FROM m00_strings" before re-ingesting
            // its own categories -- mirroring main's download_custom_files(), which
            // does the exact same wholesale wipe+rebuild. That wipe also destroys
            // whatever ImportNameOverrides() wrote into m00_strings (the
            // 'local_player_names'/'local_mytown_names' rows) at construction time,
            // every single time this update runs -- which is basically every
            // launch. main.py never hits this because it always calls
            // download_custom_files() BEFORE import_name_overrides(), in that exact
            // order, in main() (see app/main.py) -- the wipe always happens first,
            // then overrides get layered back on top. Re-running the import here,
            // right after the wipe-capable update finishes, restores that same
            // ordering so name overrides actually survive instead of silently
            // vanishing on every launch (the constructor's own ImportNameOverrides()
            // call only protects the window before this update finishes running).
            _db.ImportNameOverrides();
            _translator.UpdateGlossary(GlossaryCache.Load(_db));
            _log?.Invoke("Translation data updated.", false);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"Failed to update translation data: {ex.Message}", true);
        }
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
                _debugPacket(typeName, rawSlice, FormatHexDump(rawSlice), modSlice, modifiedHex);
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
