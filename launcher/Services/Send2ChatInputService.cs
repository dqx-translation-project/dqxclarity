using System.Runtime.InteropServices;
using System.Text;

namespace DqxClarity.Launcher.Services;

public sealed class Send2ChatInputService
{
    private const int SwRestore = 9;
    private const uint AsfwAny = uint.MaxValue;
    private const int GwlExstyle = -20;
    private const int WsExToolwindow = 0x00000080;
    private const uint InputKeyboard = 1;
    private const uint KeyeventfScancode = 0x0008;
    private const uint KeyeventfKeyup = 0x0002;
    private const uint KeyeventfExtendedkey = 0x0001;
    private const ushort VkRight = 0x27;
    private const ushort VkLeft = 0x25;
    // Extended-mode scancodes for arrow keys (prefixed 0xE0 in hardware terms).
    private const ushort ScanRight = 0x4D;
    private const ushort ScanLeft = 0x4B;

    public bool ActivateDqxWindow(int pid)
    {
        var hwnd = FindBestTopLevelWindowForPid(pid);
        if (hwnd == IntPtr.Zero) return false;

        ShowWindow(hwnd, SwRestore);
        // Windows can legally refuse foreground changes; still return true if we have a plausible HWND.
        _ = TryForceForegroundWindow(hwnd);
        _ = SetForegroundWindow(hwnd);
        return true;
    }

    public bool SendArrow(bool right)
    {
        var vk = right ? VkRight : VkLeft;
        var scan = right ? ScanRight : ScanLeft;

        var inputs = new INPUT[2];
        inputs[0] = new INPUT
        {
            type = InputKeyboard,
            U = new INPUTUNION
            {
                ki = new KEYBDINPUT
                {
                    wVk = 0,
                    wScan = scan,
                    dwFlags = KeyeventfScancode | KeyeventfExtendedkey,
                },
            },
        };
        inputs[1] = inputs[0];
        inputs[1].U.ki.dwFlags = KeyeventfScancode | KeyeventfExtendedkey | KeyeventfKeyup;

        if (SendInput(2, inputs, Marshal.SizeOf<INPUT>()) == 2)
            return true;

        // Second attempt: include VK + scancode (some stacks behave differently).
        inputs[0].U.ki.wVk = vk;
        inputs[1].U.ki.wVk = vk;
        if (SendInput(2, inputs, Marshal.SizeOf<INPUT>()) == 2)
            return true;

        // Fallback for environments where SendInput is blocked/unreliable.
        keybd_event((byte)vk, (byte)scan, KeyeventfExtendedkey, UIntPtr.Zero);
        keybd_event((byte)vk, (byte)scan, KeyeventfExtendedkey | KeyeventfKeyup, UIntPtr.Zero);
        return true;
    }

    public async Task SendArrowSequenceAsync(int pid, IReadOnlyList<bool> rights, int delayMs = 50)
    {
        if (!ActivateDqxWindow(pid)) return;
        foreach (var right in rights)
        {
            SendArrow(right);
            await Task.Delay(delayMs);
        }
    }

    private static IntPtr FindBestTopLevelWindowForPid(int pid)
    {
        var best = IntPtr.Zero;
        long bestScore = long.MinValue;

        EnumWindows((hWnd, _) =>
        {
            if (!IsWindowVisible(hWnd)) return true;
            GetWindowThreadProcessId(hWnd, out var windowPid);
            if (windowPid != pid) return true;

            if (IsToolWindow(hWnd)) return true;

            if (!TryGetWindowRect(hWnd, out var rect)) return true;
            var area = (long)rect.Width * rect.Height;
            if (area <= 0) return true;

            var titleLen = GetWindowTextLength(hWnd);
            var className = GetClassName(hWnd);

            // Prefer real UI surfaces over tiny helper/IME windows.
            long score = area;
            if (titleLen > 0) score += 5_000_000;
            if (className.Contains("IME", StringComparison.OrdinalIgnoreCase)) score -= 50_000_000;
            if (string.Equals(className, "MSCTFIME UI", StringComparison.OrdinalIgnoreCase)) score -= 50_000_000;

            if (score > bestScore)
            {
                bestScore = score;
                best = hWnd;
            }

            return true;
        }, IntPtr.Zero);

        return best;
    }

    private static bool TryForceForegroundWindow(IntPtr hwnd)
    {
        AllowSetForegroundWindow(AsfwAny);

        var fg = GetForegroundWindow();
        if (fg == hwnd) return true;

        var targetThread = GetWindowThreadProcessId(hwnd, out _);
        var fgThread = fg == IntPtr.Zero ? 0 : GetWindowThreadProcessId(fg, out _);
        var currentThread = GetCurrentThreadId();

        var attached = false;
        if (fgThread != 0 && fgThread != currentThread)
            attached = AttachThreadInput(currentThread, fgThread, true);

        try
        {
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
        }
        finally
        {
            if (attached)
                AttachThreadInput(currentThread, fgThread, false);
        }

        return GetForegroundWindow() == hwnd;
    }

    private static bool IsToolWindow(IntPtr hwnd)
    {
        var ex = GetWindowLongPtr(hwnd, GwlExstyle);
        if (ex == IntPtr.Zero) return false;
        return ((uint)ex.ToInt64() & WsExToolwindow) != 0;
    }

    private static bool TryGetWindowRect(IntPtr hwnd, out RECT rect)
    {
        rect = default;
        return GetWindowRect(hwnd, out rect);
    }

    private static string GetClassName(IntPtr hwnd)
    {
        var sb = new StringBuilder(256);
        _ = GetClassNameW(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;

        public int Width => Math.Max(0, Right - Left);
        public int Height => Math.Max(0, Bottom - Top);
    }

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

    [DllImport("user32.dll")]
    private static extern bool AllowSetForegroundWindow(uint dwProcessId);

    [DllImport("user32.dll")]
    private static extern bool BringWindowToTop(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetClassNameW")]
    private static extern int GetClassNameW(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public uint type;
        public INPUTUNION U;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct INPUTUNION
    {
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }
}
