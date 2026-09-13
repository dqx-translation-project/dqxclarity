using System.Linq;
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
//
// A name made up ENTIRELY of ・ (U+30FB) and/or ～ (U+FF5E) -- no kana, no ー
// -- is left completely untouched rather than romanized. This isn't just a
// preference: StripPunctuation below drops ・ silently (it's not a letter,
// digit, whitespace, or the special-cased ～) and folds ～ into a bare "~"
// suffix, so an all-punctuation name like "・～・" was collapsing to a
// near-empty/garbled result like "~" instead of anything resembling the
// original name.
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

    // INVESTIGATION NOTE (leaving this here so nobody re-chases the same
    // dead end): TavernRecruitmentListPacket names were showing up with
    // their first two characters left as raw, untranslated kana -- e.g.
    // "みーあ" as literal "みー" + "A". This looked like a wanakana bug, but
    // wasn't -- direct reproduction ruled out this entire dll/crate:
    //   1. The exact pinned wana_kana crate version (v4.0.0, matching the
    //      `wana_kana = "4"` pin in native/wanakana/Cargo.toml) called
    //      directly in Rust on every reported-broken name produces fully
    //      correct romaji every time, no dropped characters.
    //   2. native/wanakana/src/lib.rs compiled as a real cdylib and driven
    //      through the identical P/Invoke calling convention this file
    //      uses -- same fully correct results.
    //   3. A live debug log at this exact call site (temporarily added,
    //      since removed) confirmed it end to end: every single call this
    //      method made in the live game process returned correct romaji,
    //      with zero exceptions across hundreds of names.
    //
    // The real bug was in TavernRecruitmentListPacket.cs's own record
    // layout: HeaderBytes was off by 6 bytes, so the code was reading each
    // record's name starting 6 bytes late (usually still decoding into
    // some plausible-but-wrong run of kana, which is why it wasn't caught
    // sooner) -- for names where that shift landed on a clean 2-character
    // boundary it looked exactly like "wanakana drops the first two
    // characters," because the real first two characters got left behind
    // in what the code thought was still the previous field, and only the
    // (correctly romanized) remainder made it through. See that file's own
    // header comment for the full explanation. Nothing in this file was
    // ever the cause.
    public string ToRomaji(string text, int maxLength = 10)
    {
        if (string.IsNullOrEmpty(text)) return text;
        if (IsPunctuationOnlyName(text)) return text;
        if (!_available) return Fallback(text, maxLength);

        try
        {
            var (cleaned, suffix) = StripPunctuation(text);
            if (string.IsNullOrEmpty(cleaned)) return Cap(suffix, maxLength);

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

    // A name made up entirely of ・ (U+30FB) and/or ～ (U+FF5E) -- and
    // nothing else, no kana, no ー -- carries no linguistic content to
    // romanize. See the class doc comment for why leaving it untouched
    // (rather than running it through StripPunctuation/wanakana) matters.
    private static bool IsPunctuationOnlyName(string s) =>
        s.Length > 0 && s.All(c => c is '・' or '～');

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
