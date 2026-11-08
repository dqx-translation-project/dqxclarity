using System.Text;

namespace DqxClarity.Hooking;

// Tails the native PacketWarden.dll log file and emits new lines via a callback
// so the c# launcher's log view can surface what's happening inside the game
// process. Started by ClarityRuntime; stopped on dispose.
//
// Polling rather than FileSystemWatcher: the dll opens, appends, and closes the
// file on every Log() call (FILE_APPEND_DATA + CloseHandle), and AppendData
// doesn't reliably fire Change events through some file-system filters. A 250ms
// poll is more than fast enough — log lines are rare.
public sealed class NativeLogTail : IDisposable
{
    private readonly string _path;
    private readonly Action<string> _onLine;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private long _offset;

    public NativeLogTail(string path, Action<string> onLine)
    {
        _path = path;
        _onLine = onLine;
    }

    public void Start()
    {
        if (_loop != null) return;
        // Start from the END of the file so the user only sees lines from this session.
        try { _offset = new FileInfo(_path).Exists ? new FileInfo(_path).Length : 0; }
        catch { _offset = 0; }

        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _loop = Task.Run(() => RunAsync(ct), ct);
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _loop?.Wait(500); } catch { }
        _loop = null;
    }

    public void Dispose() => Stop();

    private async Task RunAsync(CancellationToken ct)
    {
        var partial = new StringBuilder();
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (File.Exists(_path))
                {
                    using var fs = new FileStream(_path, FileMode.Open, FileAccess.Read,
                                                  FileShare.ReadWrite | FileShare.Delete);
                    if (fs.Length < _offset)
                    {
                        // File was truncated or rotated; restart from current end.
                        _offset = fs.Length;
                    }
                    else if (fs.Length > _offset)
                    {
                        fs.Seek(_offset, SeekOrigin.Begin);
                        var buf = new byte[fs.Length - _offset];
                        var read = await fs.ReadAsync(buf, ct).ConfigureAwait(false);
                        _offset += read;

                        partial.Append(Encoding.UTF8.GetString(buf, 0, read));
                        string text = partial.ToString();
                        int lastNl = text.LastIndexOf('\n');
                        if (lastNl >= 0)
                        {
                            var complete = text[..lastNl];
                            partial.Clear();
                            partial.Append(text[(lastNl + 1)..]);
                            foreach (var line in complete.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                                _onLine(line.TrimEnd('\r'));
                        }
                    }
                }
            }
            catch (OperationCanceledException) { break; }
            catch { /* keep tailing */ }

            try { await Task.Delay(250, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }
}
