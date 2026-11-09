using System.Buffers.Binary;
using System.IO.Pipes;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DqxClarity.Hooking;

// Named-pipe server that PacketWarden.dll (inside DQXGame.exe) connects to.
// Protocol matches native/PacketWarden.cpp ExchangePacket():
//   client -> server:  [u32 packet_len][bytes packet_data]
//   server -> client:  [u8 modified]                                if modified=0
//                      [u8 modified][u32 new_len][bytes new_data]   if modified=1
//
// One pipe instance per connection. We serve a single client (the game's hook dll);
// if the client disconnects (game closes) we tear down and may re-accept on the next
// game launch via Start().
public sealed class PacketPipe : IDisposable
{
    public const string PipeName = "dqxclarity";

    public delegate byte[]? PacketHandler(ReadOnlyMemory<byte> packet);

    // Raised each time the game's hook dll connects to the pipe (on a worker thread).
    public event Action? ClientConnected;

    // Raised (on a worker thread) when the pipe server itself can't be created --
    // e.g. another dqxclarity instance already owns \\.\pipe\dqxclarity, in which
    // case the game's dll would connect to THAT instance instead of this one.
    // Reported once per distinct message, not on every retry.
    public event Action<string>? Error;

    private readonly PacketHandler _handler;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    public PacketPipe(PacketHandler handler)
    {
        _handler = handler;
    }

    public void Start()
    {
        if (_loop != null) return;
        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => RunAsync(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _loop?.Wait(2000); } catch { }
        _loop = null;
    }

    public void Dispose() => Stop();

    private async Task RunAsync(CancellationToken ct)
    {
        string? lastError = null;
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                try
                {
                    server = NamedPipeServerStreamAcl.Create(
                        PipeName,
                        PipeDirection.InOut,
                        maxNumberOfServerInstances: 1,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous,
                        inBufferSize: 0,
                        outBufferSize: 0,
                        BuildPipeSecurity());
                    lastError = null;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    var msg = $"Could not create the translation pipe ({ex.Message}). " +
                              "Is another copy of dqxclarity already running?";
                    if (msg != lastError)
                    {
                        lastError = msg;
                        try { Error?.Invoke(msg); } catch { }
                    }
                    // Back off instead of spinning a tight retry loop.
                    await Task.Delay(1000, ct).ConfigureAwait(false);
                    continue;
                }

                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                try { ClientConnected?.Invoke(); } catch { /* a listener must never break the pipe */ }
                await ServeClientAsync(server, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (IOException) { /* client disconnected, loop and re-accept */ }
            catch (Exception)  { /* swallow and re-accept */ }
            finally
            {
                server?.Dispose();
            }
        }
    }

    // The default DACL on a pipe created by an elevated process only gives
    // Everyone read access, so a non-elevated DQXGame.exe (the usual case when
    // dqxclarity is "Run as administrator" but the game is started normally)
    // gets ERROR_ACCESS_DENIED opening it read/write. Grant the current user --
    // the same account the game runs under, elevated or not -- full access,
    // alongside SYSTEM and Administrators.
    private static PipeSecurity BuildPipeSecurity()
    {
        var security = new PipeSecurity();
        var me = WindowsIdentity.GetCurrent().User;
        if (me != null)
            security.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        return security;
    }

    private async Task ServeClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        var headerBuf = new byte[4];
        while (pipe.IsConnected && !ct.IsCancellationRequested)
        {
            if (!await ReadExactAsync(pipe, headerBuf, ct).ConfigureAwait(false)) return;
            var packetLen = BinaryPrimitives.ReadUInt32LittleEndian(headerBuf);
            if (packetLen == 0 || packetLen > 0x100000) return;  // sanity cap 1MB

            var packet = new byte[packetLen];
            if (!await ReadExactAsync(pipe, packet, ct).ConfigureAwait(false)) return;

            byte[]? modified = null;
            try { modified = _handler(packet); }
            catch { modified = null; }

            if (modified is { Length: > 0 })
            {
                var resp = new byte[1 + 4 + modified.Length];
                resp[0] = 1;
                BinaryPrimitives.WriteUInt32LittleEndian(resp.AsSpan(1, 4), (uint)modified.Length);
                Buffer.BlockCopy(modified, 0, resp, 5, modified.Length);
                await pipe.WriteAsync(resp.AsMemory(), ct).ConfigureAwait(false);
            }
            else
            {
                await pipe.WriteAsync(new byte[] { 0 }, ct).ConfigureAwait(false);
            }
        }
    }

    private static async Task<bool> ReadExactAsync(PipeStream pipe, byte[] buf, CancellationToken ct)
    {
        var off = 0;
        while (off < buf.Length)
        {
            var got = await pipe.ReadAsync(buf.AsMemory(off, buf.Length - off), ct).ConfigureAwait(false);
            if (got == 0) return false;
            off += got;
        }
        return true;
    }
}
