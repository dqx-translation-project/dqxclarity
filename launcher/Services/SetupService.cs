using System.Diagnostics;
using System.Security.Cryptography;
using DqxClarity.Launcher.Models;

namespace DqxClarity.Launcher.Services;

public class SetupService
{
    private const string PythonVersion   = "3.11.3";
    private const string PythonInstaller = "python-3.11.3.exe";
    private const string PythonUrl       = "https://www.python.org/ftp/python/3.11.3/python-3.11.3.exe";
    private const string PythonMd5       = "691232496E346CE0860AEF052DD6844F"; // pragma: allowlist secret

    public event Action<SetupEvent>? Progress;
    public event Action? UacPrompt;

    private void Emit(string step, string status, string message) =>
        Progress?.Invoke(new SetupEvent(step, status, message));

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

    private static void CheckPathSafety(string dir)
    {
        if (dir.Contains("onedrive", StringComparison.OrdinalIgnoreCase))
            throw new Exception(
                "dqxclarity is running from a OneDrive folder. OneDrive sync interferes with the database. " +
                "Please move the application to a non-synced location and try again.");
    }

    private static string? FindPythonExe()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Python\PythonCore\3.11-32\InstallPath");
            if (key?.GetValue("ExecutablePath") is string exePath && File.Exists(exePath))
                return exePath;
        }
        catch { }
        return null;
    }

    private async Task DownloadAndInstallPython(string dir, CancellationToken ct)
    {
        var installerPath = Path.Combine(dir, PythonInstaller);
        Emit("python_install", "running", $"Downloading Python {PythonVersion} (32-bit)...");

        using var http = new HttpClient();
        var bytes = await http.GetByteArrayAsync(PythonUrl, ct);

        var digest = Convert.ToHexString(MD5.HashData(bytes));
        if (!digest.Equals(PythonMd5, StringComparison.OrdinalIgnoreCase))
            throw new Exception($"Python installer MD5 mismatch (got {digest}, expected {PythonMd5}). Please try again.");

        await File.WriteAllBytesAsync(installerPath, bytes, ct);

        Emit("python_install", "running", "Running installer silently, please wait...");
        UacPrompt?.Invoke();

        var logPath = Path.Combine(dir, "python-install.log");
        var psi = new ProcessStartInfo(installerPath)
        {
            Arguments = $"/quiet InstallAllUsers=1 PrependPath=0 Include_test=0 /log \"{logPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        var proc = Process.Start(psi) ?? throw new Exception("Failed to start Python installer");
        await proc.WaitForExitAsync(ct);

        try { File.Delete(installerPath); } catch { }

        if (proc.ExitCode != 0)
            throw new Exception(
                $"Python installer exited with an error. If your antivirus blocked it, " +
                $"add an exclusion for this folder and try again. Installer log: {logPath}");

        // clean up any python-install* files
        foreach (var f in Directory.GetFiles(dir, "python-install*"))
            try { File.Delete(f); } catch { }
    }

    private static async Task SetupVenv(string pythonExe, string venvDir, CancellationToken ct)
    {
        if (File.Exists(Path.Combine(venvDir, "Scripts", "python.exe")))
            return;

        if (Directory.Exists(venvDir))
            Directory.Delete(venvDir, recursive: true);

        var psi = new ProcessStartInfo(pythonExe, $"-m venv \"{venvDir}\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        var proc = Process.Start(psi) ?? throw new Exception("Failed to create venv");
        await proc.WaitForExitAsync(ct);

        if (proc.ExitCode != 0)
            throw new Exception(
                "Failed to create virtual environment. If your antivirus is blocking Python, " +
                "add a folder exclusion for this directory.");
    }

    private static string? FindPyproject(string exeDir)
    {
        var dir = exeDir;
        for (int i = 0; i < 4; i++)
        {
            var candidate = Path.Combine(dir, "pyproject.toml");
            if (File.Exists(candidate))
                return Path.GetFullPath(candidate);
            dir = Path.Combine(dir, "..");
        }
        return null;
    }

    private async Task InstallDeps(string venvDir, string exeDir, Action<string> onPipLine, CancellationToken ct)
    {
        var pyprojectPath = FindPyproject(exeDir);
        if (pyprojectPath == null)
            throw new Exception(
                "Could not find pyproject.toml. Make sure the launcher is placed in the dqxclarity installation folder.");

        var pyprojectDir = Path.GetDirectoryName(pyprojectPath)!;
        var content = await File.ReadAllBytesAsync(pyprojectPath, ct);
        var currentHash = Convert.ToHexString(MD5.HashData(content));

        var hashFile = Path.Combine(venvDir, ".requirements_hash");
        var storedHash = File.Exists(hashFile) ? (await File.ReadAllTextAsync(hashFile, ct)).Trim() : "";

        if (currentHash == storedHash) return;

        var pipExe = Path.Combine(venvDir, "Scripts", "pip.exe");
        var psi = new ProcessStartInfo(pipExe, "install --disable-pip-version-check . --quiet")
        {
            WorkingDirectory = pyprojectDir,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        var proc = Process.Start(psi) ?? throw new Exception("Failed to launch pip");

        proc.OutputDataReceived += (_, e) => { if (e.Data != null) onPipLine(e.Data); };
        proc.ErrorDataReceived  += (_, e) => { if (e.Data != null) onPipLine(e.Data); };
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();
        await proc.WaitForExitAsync(ct);

        if (proc.ExitCode != 0)
            throw new Exception("pip install failed. Please try again.");

        await File.WriteAllTextAsync(hashFile, currentHash, ct);
    }

    private static async Task VerifyInstall(string venvDir, CancellationToken ct)
    {
        var python = Path.Combine(venvDir, "Scripts", "python.exe");
        var psi = new ProcessStartInfo(python, "-c \"import pykakasi\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        var proc = Process.Start(psi) ?? throw new Exception("Failed to run verification");
        await proc.WaitForExitAsync(ct);
        if (proc.ExitCode != 0)
            throw new Exception(
                "Dependency verification failed. The virtual environment may be corrupt. " +
                "Please delete the venv folder and try again.");
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        var dir = ExeDir();
        var venvDir = Path.Combine(dir, "venv");

        Emit("path_check", "running", "Checking installation path...");
        CheckPathSafety(dir);
        Emit("path_check", "done", "Installation path is safe.");

        Emit("python_check", "running", "Looking for Python 3.11 (32-bit)...");
        var pythonExe = FindPythonExe();
        if (pythonExe == null)
        {
            Emit("python_check", "done", "Python 3.11 (32-bit) not found — will install.");
            await DownloadAndInstallPython(dir, ct);
            Emit("python_install", "done", "Python 3.11.3 installed successfully.");
            pythonExe = FindPythonExe() ?? throw new Exception(
                "Python was installed but could not be located. Please restart the launcher.");
        }
        else
        {
            Emit("python_check", "done", $"Found Python at {pythonExe}");
        }

        Emit("venv_setup", "running", "Setting up virtual environment...");
        await SetupVenv(pythonExe, venvDir, ct);
        Emit("venv_setup", "done", "Virtual environment ready.");

        Emit("deps_install", "running", "Checking dependencies...");
        await InstallDeps(venvDir, dir, line =>
        {
            if (!string.IsNullOrWhiteSpace(line))
                Emit("pip_output", "info", line);
        }, ct);
        Emit("deps_install", "done", "Dependencies are up to date.");

        Emit("verify", "running", "Verifying installation...");
        await VerifyInstall(venvDir, ct);
        Emit("verify", "done", "Installation verified.");
    }
}
