using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace DqxClarity.Translation;

// P/Invoke wrapper around native/wanakana.dll (rust cdylib). Falls back to
// returning the input untouched if the dll isn't present or the call fails —
// nameplates are best-effort, not load-bearing.
//
// Kana-only: kanji passes through unromanized. That's the trade-off documented
// in the plan; covers ~all dqx player names which are kana-restricted.
public sealed class WanaKanaRomanizer : IRomanizer
{
    private const string Dll = "wanakana";

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern int wanakana_to_romaji(byte[] input, byte[] output, int outCapacity);

    private static readonly bool _available;

    static WanaKanaRomanizer()
    {
        EnsureExtracted();
        NativeLibrary.SetDllImportResolver(typeof(WanaKanaRomanizer).Assembly, Resolve);
        _available = ProbeAvailable();
    }

    // Extracts the embedded wanakana.dll next to the exe on first use so the
    // dll-import resolver below can find it. No-op if the embedded resource
    // doesn't exist (e.g. nobody ran `task wanakana` yet).
    private static string MiscFilesDir()
    {
        var exe = Environment.ProcessPath ?? AppContext.BaseDirectory;
        return Path.Combine(Path.GetDirectoryName(exe) ?? AppContext.BaseDirectory, "misc_files");
    }

    private static void EnsureExtracted()
    {
        var dir = MiscFilesDir();
        var dst = Path.Combine(dir, "wanakana.dll");
        if (File.Exists(dst)) return;

        using var stream = typeof(WanaKanaRomanizer).Assembly.GetManifestResourceStream("wanakana.dll");
        if (stream == null) return;
        try
        {
            Directory.CreateDirectory(dir);
            using var fs = File.Create(dst);
            stream.CopyTo(fs);
        }
        catch { /* file in use or permission denied — let probe handle it */ }
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, Dll, StringComparison.OrdinalIgnoreCase))
            return IntPtr.Zero;

        var candidate = Path.Combine(MiscFilesDir(), "wanakana.dll");
        if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out var handle))
            return handle;
        return IntPtr.Zero;
    }

    public string ToRomaji(string text, int maxLength = 10)
    {
        if (string.IsNullOrEmpty(text)) return text;
        if (!_available) return Fallback(text, maxLength);

        try
        {
            var (cleaned, suffix) = StripPunctuation(text);
            // utf-8 expands at most ~3x for japanese; allow generous headroom plus the null terminator
            var inputBytes = Encoding.UTF8.GetBytes(cleaned + "\0");
            var capacity = Math.Max(64, cleaned.Length * 4 + 1);
            var output = new byte[capacity];

            var written = wanakana_to_romaji(inputBytes, output, capacity);
            if (written < 0) return Fallback(text, maxLength);

            var result = Encoding.UTF8.GetString(output, 0, written);
            return Cap(Title(result) + suffix, maxLength);
        }
        catch
        {
            return Fallback(text, maxLength);
        }
    }

    private static bool ProbeAvailable()
    {
        try
        {
            var input = Encoding.UTF8.GetBytes("\0");
            var output = new byte[16];
            _ = wanakana_to_romaji(input, output, output.Length);
            return true;
        }
        catch (DllNotFoundException) { return false; }
        catch { return false; }
    }

    // Strip punctuation before romanizing so wanakana doesn't mangle symbols
    // into unexpected ascii. ～ is collected into a suffix appended after
    // romanization + title-casing so it doesn't interfere with casing.
    private static (string Cleaned, string Suffix) StripPunctuation(string s)
    {
        var cleaned = new StringBuilder(s.Length);
        var suffix = new StringBuilder();
        foreach (var c in s)
        {
            if (c == '～')
                suffix.Append('~');
            else if (char.IsLetterOrDigit(c) || char.IsWhiteSpace(c))
                cleaned.Append(c);
        }
        return (cleaned.ToString(), suffix.ToString());
    }

    // Applies .title() casing (capitalize first letter of each word).
    private static string Title(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        var sb = new StringBuilder(s.Length);
        var nextUpper = true;
        foreach (var c in s)
        {
            if (char.IsWhiteSpace(c)) { sb.Append(c); nextUpper = true; continue; }
            sb.Append(nextUpper ? char.ToUpperInvariant(c) : char.ToLowerInvariant(c));
            nextUpper = false;
        }
        return sb.ToString();
    }

    private static string Cap(string s, int max) =>
        s.Length <= max ? s : s[..max];

    private static string Fallback(string s, int max) =>
        s.Length <= max ? s : s[..max];
}
