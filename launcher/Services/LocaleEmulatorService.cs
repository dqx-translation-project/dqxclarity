using System.Runtime.InteropServices;
using System.Text;

namespace DqxClarity.Launcher.Services;

internal static class LocaleEmulatorService
{
    private static string NativeDir()
    {
        var exe = Environment.ProcessPath ?? AppContext.BaseDirectory;
        return Path.Combine(Path.GetDirectoryName(exe) ?? AppContext.BaseDirectory, "misc_files");
    }

    internal static void EnsureExtracted()
    {
        using var stream = typeof(LocaleEmulatorService).Assembly.GetManifestResourceStream("LocaleHook.dll");
        if (stream == null) return;
        Directory.CreateDirectory(NativeDir());
        using var fs = File.Create(Path.Combine(NativeDir(), "LocaleHook.dll"));
        stream.CopyTo(fs);
    }

    internal static bool IsAvailable() =>
        File.Exists(Path.Combine(NativeDir(), "LocaleHook.dll"));

    // Creates the game process and injects LocaleHook.dll before any user input is possible.
    internal static bool Launch(string applicationName, string? arguments, string workingDirectory)
    {
        var dllPath = Path.Combine(NativeDir(), "LocaleHook.dll");
        var cmdLine = $"\"{applicationName}\"";
        if (!string.IsNullOrEmpty(arguments))
            cmdLine += $" {arguments}";

        var si = new STARTUPINFOW { cb = Marshal.SizeOf<STARTUPINFOW>() };
        if (!CreateProcessW(applicationName, cmdLine, IntPtr.Zero, IntPtr.Zero,
                            false, 0, IntPtr.Zero, workingDirectory, ref si, out var pi))
            return false;

        try   { return InjectWithRetry(pi.hProcess, dllPath); }
        finally
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    private static bool InjectWithRetry(IntPtr hProcess, string dllPath)
    {
        for (int i = 0; i < 20; i++)
        {
            Thread.Sleep(50);
            var loadLibW = GetWow64LoadLibraryW(hProcess);
            if (loadLibW != 0 && TryInject(hProcess, dllPath, (IntPtr)(long)loadLibW))
                return true;
        }
        return false;
    }

    private static bool TryInject(IntPtr hProcess, string dllPath, IntPtr loadLibW)
    {
        var bytes  = Encoding.Unicode.GetBytes(dllPath + "\0");
        var remote = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)bytes.Length, 0x3000, 0x04);
        if (remote == IntPtr.Zero) return false;
        try
        {
            if (!WriteProcessMemory(hProcess, remote, bytes, (uint)bytes.Length, out _))
                return false;
            var thread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibW, remote, 0, out _);
            if (thread == IntPtr.Zero) return false;
            WaitForSingleObject(thread, 10000);
            GetExitCodeThread(thread, out var code);
            CloseHandle(thread);
            return code != 0; // LoadLibraryW returns the HMODULE on success, 0 on failure
        }
        finally { VirtualFreeEx(hProcess, remote, 0, 0x8000); }
    }

    // Returns the 32-bit virtual address of LoadLibraryW in a WOW64 target process.
    // Strategy: enumerate the target's 32-bit modules to find kernel32's base address,
    // then parse SysWOW64\kernel32.dll's PE exports to get LoadLibraryW's RVA.
    private static uint GetWow64LoadLibraryW(IntPtr hProcess)
    {
        var k32Base = GetModuleBaseInProcess(hProcess, "kernel32.dll");
        if (k32Base == 0) return 0;

        var sysWow64Kernel32 = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "SysWOW64", "kernel32.dll");

        var rva = GetExportRva(sysWow64Kernel32, "LoadLibraryW");
        return rva == 0 ? 0 : k32Base + rva;
    }

    // Enumerates a WOW64 process's 32-bit modules and returns the base address of the named one.
    private static uint GetModuleBaseInProcess(IntPtr hProcess, string name)
    {
        const uint LIST_MODULES_32BIT = 0x01;
        K32EnumProcessModulesEx(hProcess, null!, 0, out var needed, LIST_MODULES_32BIT);
        if (needed == 0) return 0;

        var mods = new IntPtr[needed / (uint)IntPtr.Size];
        if (!K32EnumProcessModulesEx(hProcess, mods, needed, out _, LIST_MODULES_32BIT))
            return 0;

        var sb = new StringBuilder(260);
        foreach (var mod in mods)
        {
            sb.Clear();
            if (K32GetModuleFileNameExW(hProcess, mod, sb, 260) > 0 &&
                Path.GetFileName(sb.ToString()).Equals(name, StringComparison.OrdinalIgnoreCase))
                return (uint)(mod.ToInt64() & 0xFFFF_FFFF);
        }
        return 0;
    }

    // Loads a PE file as an image resource and walks its export table to find the named export's RVA.
    private static uint GetExportRva(string dllPath, string exportName)
    {
        // LOAD_LIBRARY_AS_DATAFILE (0x2) | LOAD_LIBRARY_AS_IMAGE_RESOURCE (0x20) maps the file
        // as an image so RVAs are valid as memory offsets from the base.
        var hMod = LoadLibraryExW(dllPath, IntPtr.Zero, 0x22);
        if (hMod == IntPtr.Zero) return 0;
        try
        {
            // The returned handle has the low 2 bits set as flags; clear them for the real base.
            var b = new IntPtr(hMod.ToInt64() & ~3L);

            var lfanew = Marshal.ReadInt32(b, 0x3C);
            // PE sig (4) + FileHeader (20) + offset 96 into OptionalHeader32 = export dir RVA
            var expRva = (uint)Marshal.ReadInt32(b, lfanew + 4 + 20 + 96);
            if (expRva == 0) return 0;

            var exp    = new IntPtr(b.ToInt64() + expRva);
            int nNames = Marshal.ReadInt32(exp, 24);
            var rNames = (uint)Marshal.ReadInt32(exp, 32);
            var rOrds  = (uint)Marshal.ReadInt32(exp, 36);
            var rFuncs = (uint)Marshal.ReadInt32(exp, 28);

            for (int i = 0; i < nNames; i++)
            {
                var nameRva = (uint)Marshal.ReadInt32(new IntPtr(b.ToInt64() + rNames), i * 4);
                var name    = Marshal.PtrToStringAnsi(new IntPtr(b.ToInt64() + nameRva));
                if (name == exportName)
                {
                    var ord = (ushort)Marshal.ReadInt16(new IntPtr(b.ToInt64() + rOrds), i * 2);
                    return (uint)Marshal.ReadInt32(new IntPtr(b.ToInt64() + rFuncs), ord * 4);
                }
            }
            return 0;
        }
        finally { FreeLibrary(hMod); }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string? lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string? lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    private static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll")]
    private static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool K32EnumProcessModulesEx(
        IntPtr hProcess, IntPtr[]? lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint K32GetModuleFileNameExW(
        IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, uint nSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOW
    {
        public  int    cb;
        private IntPtr lpReserved, lpDesktop, lpTitle;
        private uint   dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        private short  wShowWindow, cbReserved2;
        private IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public uint   dwProcessId, dwThreadId;
    }
}
