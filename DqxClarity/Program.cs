using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using Avalonia;
using Avalonia.Win32;

namespace DqxClarity;

internal sealed class Program
{
    [DllImport("user32.dll")]   private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")]   private static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("shell32.dll")]  private static extern int SetCurrentProcessExplicitAppUserModelID([MarshalAs(UnmanagedType.LPWStr)] string appId);

    private const int SW_RESTORE = 9;

    [STAThread]
    public static void Main(string[] args)
    {
        var bak = (Environment.ProcessPath ?? "") + ".bak";
        if (File.Exists(bak))
            for (int i = 0; i < 5; i++)
            {
                try { File.Delete(bak); break; }
                catch { Thread.Sleep(200); }
            }

        SetCurrentProcessExplicitAppUserModelID("dqxclarity.launcher");

        // Single-instance guard
        using var mutex = new Mutex(true, "DqxClarityLauncher-{A3F2C1D0-4B5E-4F6A-8C7D-9E0B1A2C3D4E}", out var isNew);
        if (!isNew)
        {
            BringExistingInstanceToFront();
            return;
        }

        BuildAvaloniaApp(args).StartWithClassicDesktopLifetime(args);
    }

    private static void BringExistingInstanceToFront()
    {
        var current  = Process.GetCurrentProcess();
        var existing = Process.GetProcessesByName(current.ProcessName)
            .FirstOrDefault(p => p.Id != current.Id && p.MainWindowHandle != IntPtr.Zero);
        if (existing == null) return;

        var hwnd = existing.MainWindowHandle;
        ShowWindow(hwnd, SW_RESTORE);      // un-minimise if minimised
        SetForegroundWindow(hwnd);         // bring to front / activate
    }

    public static AppBuilder BuildAvaloniaApp(string[] args) =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .With(new Win32PlatformOptions
            {
                // Software rendering avoids DirectComposition/GPU issues in Wine/Proton
                RenderingMode = [Win32RenderingMode.Software]
            })
            .UseSkia()
            .LogToTrace();
}
