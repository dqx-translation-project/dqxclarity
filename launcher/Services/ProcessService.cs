using System.Diagnostics;
using System.Text.RegularExpressions;
using DqxClarity.Launcher.Models;

namespace DqxClarity.Launcher.Services;

public class ProcessService
{
    private Process? _child;
    private bool _userStopped;
    private readonly object _lock = new();

    private static readonly Regex AnsiRegex =
        new(@"\x1b\[([0-9;]*)m", RegexOptions.Compiled);

    private static readonly Dictionary<int, string> AnsiColors = new()
    {
        [30] = "#595959", [31] = "#CC0000", [32] = "#4E9A06", [33] = "#C4A000",
        [34] = "#3465A4", [35] = "#75507B", [36] = "#06989A", [37] = "#D3D7CF",
        [90] = "#555753", [91] = "#EF2929", [92] = "#8AE234", [93] = "#FCE94F",
        [94] = "#729FCF", [95] = "#AD7FA8", [96] = "#34E2E2", [97] = "#EEEEEC",
    };

    private static (string PlainText, IReadOnlyList<AnsiRun> Runs) ParseAnsi(string s)
    {
        var runs = new List<AnsiRun>();
        string? currentColor = null;
        int pos = 0;

        foreach (Match m in AnsiRegex.Matches(s))
        {
            if (m.Index > pos)
                runs.Add(new AnsiRun(s[pos..m.Index], currentColor));

            pos = m.Index + m.Length;

            var codes = m.Groups[1].Value;
            if (string.IsNullOrEmpty(codes))
            {
                currentColor = null;
            }
            else
            {
                foreach (var part in codes.Split(';'))
                {
                    if (int.TryParse(part, out int code))
                    {
                        if (code == 0) currentColor = null;
                        else if (AnsiColors.TryGetValue(code, out var hex)) currentColor = hex;
                    }
                }
            }
        }

        if (pos < s.Length)
            runs.Add(new AnsiRun(s[pos..], currentColor));

        var plain = runs.Count > 0 ? string.Concat(runs.Select(r => r.Text)) : s;
        return (plain, runs);
    }

    public event Action<LogLine>? LogLine;
    public event Action<bool>? ProcessExited; // bool = wasError

    private static string ExeDir()
    {
        var exe = Environment.ProcessPath ?? throw new Exception("Cannot determine executable path");
        return Path.GetDirectoryName(exe) ?? throw new Exception("Cannot determine executable directory");
    }

    private static string FindAppDir(string exeDir)
    {
        var dir = exeDir;
        for (int i = 0; i < 4; i++)
        {
            if (File.Exists(Path.Combine(dir, "main.py")))
                return Path.GetFullPath(dir);
            dir = Path.Combine(dir, "..");
        }
        return Path.GetFullPath(Path.Combine(exeDir, ".."));
    }

    public void Launch(IEnumerable<string> args)
    {
        var dir = ExeDir();
        var python = Path.Combine(dir, "venv", "Scripts", "python.exe");

        if (!File.Exists(python))
            throw new FileNotFoundException("Python executable not found in venv. Please run setup first.");

        var appDir = FindAppDir(dir);
        var argList = string.Join(" ", args.Select(a => $"\"{a}\""));
        var psi = new ProcessStartInfo(python, $"-m main {argList}")
        {
            WorkingDirectory = appDir,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding  = System.Text.Encoding.UTF8,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        psi.Environment["PYTHONUTF8"] = "1";
        psi.Environment["PYTHONWARNINGS"] = "ignore::UserWarning";

        var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };

        proc.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                var (text, runs) = ParseAnsi(e.Data);
                LogLine?.Invoke(new LogLine { Level = "info", Text = text, Runs = runs });
            }
        };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                var (text, runs) = ParseAnsi(e.Data);
                LogLine?.Invoke(new LogLine { Level = "error", Text = text, Runs = runs });
            }
        };
        proc.Exited += (_, _) =>
        {
            bool wasUser;
            lock (_lock)
            {
                _child = null;
                wasUser = _userStopped;
                _userStopped = false;
            }
            if (!wasUser)
            {
                LogLine?.Invoke(new LogLine { Level = "info", Text = "-- process exited --" });
                var isError = proc.ExitCode != 0;
                ProcessExited?.Invoke(isError);
            }
        };

        lock (_lock)
        {
            _child = proc;
            _userStopped = false;
        }

        proc.Start();
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();
    }

    public void Stop()
    {
        Process? proc;
        lock (_lock)
        {
            proc = _child;
            if (proc == null) return;
            _userStopped = true;
        }

        try
        {
            var psi = new ProcessStartInfo("taskkill", $"/PID {proc.Id} /T /F")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
            };
            Process.Start(psi)?.WaitForExit();
        }
        catch { }

        ProcessExited?.Invoke(false);
    }

    public bool IsRunning()
    {
        lock (_lock) return _child != null;
    }
}
