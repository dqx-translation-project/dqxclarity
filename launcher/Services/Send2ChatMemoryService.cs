using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DqxClarity.Launcher.Services;

public enum AttachResult
{
    Ok,
    NotRunning,
    AccessDenied,
    ElevationMismatch,
    ModuleNotFound,
}

public sealed class Send2ChatMemoryService : IDisposable
{
    private const string ModuleName = "DQXGame.exe";
    private const uint BaseOffset = 0x01C8AA3C;
    private static readonly uint[] PointerChain = [0x8, 0x94, 0x4, 0x4, 0x98, 0x2DC, 0x0];
    public const int MaxChars = 20;

    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessVmWrite = 0x0020;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessAccess = ProcessVmRead | ProcessVmWrite | ProcessVmOperation | ProcessQueryInformation;

    private const uint Th32csSnapModule = 0x00000008;
    private const uint Th32csSnapModule32 = 0x00000010;
    private const uint TokenQuery = 0x0008;
    private const int TokenElevationClass = 20;
    private static readonly IntPtr InvalidHandleValue = new(-1);

    private IntPtr _processHandle = IntPtr.Zero;
    private int _pid;
    private uint _moduleBase;

    public bool IsAttached => _processHandle != IntPtr.Zero;
    public int AttachedPid => _pid;

    public AttachResult TryAttach(out string error)
    {
        error = "";
        ResetAttachment();

        var proc = Process.GetProcessesByName("DQXGame").FirstOrDefault();
        if (proc == null)
        {
            error = "DQX not running.";
            return AttachResult.NotRunning;
        }

        _pid = proc.Id;
        _processHandle = OpenProcess(ProcessAccess, false, _pid);
        if (_processHandle == IntPtr.Zero)
        {
            var win32Err = Marshal.GetLastWin32Error();
            error = win32Err == 5
                ? "Access denied. Run launcher as administrator."
                : $"Failed to open DQX process (error {win32Err}).";
            return AttachResult.AccessDenied;
        }

        if (IsProcessElevated(_pid) && !IsCurrentProcessElevated())
        {
            error = "DQX is running elevated; launcher is not.";
            ResetAttachment();
            return AttachResult.ElevationMismatch;
        }

        _moduleBase = GetModuleBaseAddress((uint)_pid, ModuleName);
        if (_moduleBase == 0)
        {
            error = "DQX module not found.";
            ResetAttachment();
            return AttachResult.ModuleNotFound;
        }

        return AttachResult.Ok;
    }

    public bool TryResolveBufferAddress(out uint address, out string error)
    {
        address = 0;
        error = "";
        if (!IsAttached)
        {
            error = "DQX not attached.";
            return false;
        }

        address = ResolveBufferAddress();
        if (address == 0)
        {
            error = "Failed to resolve chat buffer address.";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Writes one chat character: the UTF-8 bytes at <paramref name="address"/>, advances the
    /// cursor by the byte length, then writes a 0x00 terminator at the new position *without*
    /// advancing past it. The next character's bytes overwrite that null, so the final buffer
    /// is a contiguous UTF-8 string with a single trailing 0x00.
    /// </summary>
    public bool WriteAhkChatChar(ref uint address, char ch, out string error)
    {
        error = "";
        if (!IsAttached)
        {
            error = "DQX not attached.";
            return false;
        }

        Span<byte> utf8 = stackalloc byte[4];
        var written = Encoding.UTF8.GetBytes(new ReadOnlySpan<char>(in ch), utf8);
        if (written <= 0)
            return true;

        if (!WriteBytes(address, utf8[..written].ToArray()))
        {
            error = $"Failed to write chat bytes ({new Win32Exception(Marshal.GetLastWin32Error()).Message}).";
            return false;
        }

        address += (uint)written;

        if (!WriteBytes(address, [0x00]))
        {
            error = $"Failed to write chat terminator ({new Win32Exception(Marshal.GetLastWin32Error()).Message}).";
            return false;
        }

        return true;
    }

    public void Dispose() => ResetAttachment();

    public static string TruncateToMaxChars(string text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        var runes = text.EnumerateRunes().Take(MaxChars);
        var sb = new StringBuilder();
        foreach (var rune in runes) sb.Append(rune.ToString());
        return sb.ToString();
    }

    private uint ResolveBufferAddress()
    {
        var address = _moduleBase + BaseOffset;
        foreach (var offset in PointerChain)
        {
            if (!ReadUInt32(address, out var value))
                return 0;
            address = value + offset;
        }
        return address;
    }

    private bool ReadUInt32(uint address, out uint value)
    {
        value = 0;
        var buf = new byte[4];
        if (!ReadProcessMemory(_processHandle, (IntPtr)address, buf, buf.Length, out var bytesRead))
            return false;
        if (bytesRead.ToInt64() < 4)
            return false;
        value = BitConverter.ToUInt32(buf, 0);
        return true;
    }

    private bool WriteBytes(uint address, byte[] bytes) =>
        WriteProcessMemory(_processHandle, (IntPtr)address, bytes, bytes.Length, out var bytesWritten) &&
        bytesWritten.ToInt64() == bytes.Length;

    private void ResetAttachment()
    {
        if (_processHandle != IntPtr.Zero)
        {
            CloseHandle(_processHandle);
            _processHandle = IntPtr.Zero;
        }
        _pid = 0;
        _moduleBase = 0;
    }

    private static bool IsCurrentProcessElevated() => IsProcessElevated(Environment.ProcessId);

    private static bool IsProcessElevated(int pid)
    {
        var handle = OpenProcess(ProcessQueryInformation, false, pid);
        if (handle == IntPtr.Zero)
            return false;

        try
        {
            if (!OpenProcessToken(handle, TokenQuery, out var tokenHandle))
                return false;
            try
            {
                var size = Marshal.SizeOf<TOKEN_ELEVATION>();
                var ptr = Marshal.AllocHGlobal(size);
                try
                {
                    if (!GetTokenInformation(tokenHandle, TokenElevationClass, ptr, size, out _))
                        return false;
                    var elevation = Marshal.PtrToStructure<TOKEN_ELEVATION>(ptr);
                    return elevation.TokenIsElevated != 0;
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }
            finally
            {
                CloseHandle(tokenHandle);
            }
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static uint GetModuleBaseAddress(uint pid, string moduleName)
    {
        var snapshot = CreateToolhelp32Snapshot(Th32csSnapModule | Th32csSnapModule32, pid);
        if (snapshot == InvalidHandleValue || snapshot == IntPtr.Zero)
            return 0;

        try
        {
            var moduleEntry = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32W>() };
            if (!Module32FirstW(snapshot, ref moduleEntry))
                return 0;

            do
            {
                if (string.Equals(moduleEntry.szModule, moduleName, StringComparison.OrdinalIgnoreCase))
                    return (uint)moduleEntry.modBaseAddr.ToInt64();
            }
            while (Module32NextW(snapshot, ref moduleEntry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return 0;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Module32FirstW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Module32NextW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_ELEVATION
    {
        public int TokenIsElevated;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MODULEENTRY32W
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }
}
