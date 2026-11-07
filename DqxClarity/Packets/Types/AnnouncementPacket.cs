using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// Orange system announcements -- the server-pushed lines that scroll across the
// top of the screen ("the DQX Shop clerk is visiting Megistris...", maintenance
// notices and so on). Opcode 0x1D, marker 0xA83C.
//
// One announcement arrives as several packets, one per line, in order. The text
// is server side and the on-screen space is small, so there is no automatic
// translation: every line needs a hand-written entry in m00 'custom_announcements'
// (and a line with no entry is left alone).
//
// Layout (after opcode + marker), from four captures of one announcement:
//   header   12 bytes -- byte 0 is the line number within the announcement (0, 1,
//            2, 3 in the captures), the other 11 are zero. Passthrough.
//   text     cstring (utf-8, null-terminated, no length prefix)
//   tail     8 bytes -- 02 00 00 00 00 00 00 00 in every capture. The 02 is
//            probably the colour/kind (these are the orange ones); not
//            checked, so any other kind sent on this marker is translated too.
//            Passthrough.
// The text is simply replaced in place and the frame size follows from the new
// length, the same as TopLeftCornerTextPacket (no length field, no fixed slot).
// Not crash-tested with text of a different length.
//
// --- custom_announcements ---
// The json is { "<line>": { "<japanese>": "<english>" }, ... } like the other
// custom files, which the importer flattens to japanese -> english, so the line
// number is only there for the author's benefit and is not used for lookup.
//
//   Fixed line:  an exact match on the whole japanese line.
//   Template:    a japanese key containing <placeholders>. The key is matched as a
//                whole line, with each placeholder capturing part of it, and the
//                english value is filled in from those captures:
//
//     "<month>月<day>日(<dow>)<hour>:<minute>に帰ります":
//         "leave on <month>/<day> at <hour>:<minute> JST."
//     "DQXショップ店員「<jpnpcname>」が": "the DQX Shop clerk <engnpcname> will"
//
//   In the key:
//     <jpnpcname> <jpplayername> <jpitemname> <jpmonstername>   any text
//     <dow>                                                     one of 日月火水木金土
//     <anything-else>                                           digits, e.g. <month> <day> <hour> <minute> <number>
//       (an unrecognised name matches any text)
//   In the value:
//     <engnpcname>       the english for the captured <jpnpcname> (npcs +
//                        custom_npc_name_overrides, then romaji)
//     <engplayername>    local_player_names, then romaji
//     <engitemname>      items;  <engmonstername>  monsters. No romaji fallback
//                        here -- if they're not in the dictionary the line is
//                        left untranslated and logged.
//     <dow>              the captured weekday as Mon/Tue/...
//     <name>             any other captured placeholder, as written (full-width
//                        digits become ASCII)
//
// A japanese line that gets no translation is appended to
// <exe dir>/logs/announcements.log as a json entry ready to paste into
// custom_announcements -- see UntranslatedTextLog.
//
// Samples: docs/packets/references/announcement_1 .. announcement_4
public sealed class AnnouncementPacket : IPacket
{
    private const int HeaderBytes = 12;

    private static readonly Regex PlaceholderRe = new(@"<([A-Za-z0-9_]+)>", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Dictionary<char, string> WeekdayEn = new()
    {
        ['日'] = "Sun", ['月'] = "Mon", ['火'] = "Tue", ['水'] = "Wed", ['木'] = "Thu", ['金'] = "Fri", ['土'] = "Sat",
    };

    // Compiled templates, one list per dictionary instance (the dictionary is
    // rebuilt when the active character changes, which drops the old list).
    private static readonly ConditionalWeakTable<Dictionary<string, string>, List<Template>> TemplateCache = new();

    private sealed record Template(Regex Pattern, string English);

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private string _text = "";
    private int _terminator = -1;

    public byte[]? ModifiedData { get; private set; }

    public AnnouncementPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes + 1) return;
        var terminator = Array.IndexOf(_raw, (byte)0, HeaderBytes);
        if (terminator < 0) return; // unterminated text: not the shape we know
        _terminator = terminator;
        _text = Encoding.UTF8.GetString(_raw, HeaderBytes, terminator - HeaderBytes);
    }

    public void Build()
    {
        if (_terminator < 0 || _text.Length == 0) return;
        if (!Translator.IsTextJapanese(_text)) return; // already english (the hook re-reading its own write)

        var dict = _deps.M00Dict("custom_announcements");
        var english = Lookup(_text, dict);
        if (string.IsNullOrEmpty(english))
        {
            _deps.AnnouncementLog?.Record(_text);
            return;
        }
        if (english == _text) return;

        var textBytes = Encoding.UTF8.GetBytes(english);
        var result = new byte[HeaderBytes + textBytes.Length + (_raw.Length - _terminator)];
        Buffer.BlockCopy(_raw, 0, result, 0, HeaderBytes);
        Buffer.BlockCopy(textBytes, 0, result, HeaderBytes, textBytes.Length);
        // terminator + tail, copied as it came
        Buffer.BlockCopy(_raw, _terminator, result, HeaderBytes + textBytes.Length, _raw.Length - _terminator);
        ModifiedData = result;
    }

    private string? Lookup(string text, Dictionary<string, string> dict)
    {
        if (dict.TryGetValue(text, out var fixedLine) && !string.IsNullOrEmpty(fixedLine)) return fixedLine;

        foreach (var template in GetTemplates(dict))
        {
            var match = template.Pattern.Match(text);
            if (!match.Success) continue;
            var filled = Fill(template.English, match);
            if (filled != null) return filled;
        }
        return null;
    }

    private static List<Template> GetTemplates(Dictionary<string, string> dict)
    {
        return TemplateCache.GetValue(dict, d =>
        {
            var list = new List<Template>();
            foreach (var (ja, en) in d)
            {
                if (string.IsNullOrEmpty(en) || !PlaceholderRe.IsMatch(ja)) continue;
                var pattern = CompileKey(ja);
                if (pattern != null) list.Add(new Template(pattern, en));
            }
            return list;
        });
    }

    private static Regex? CompileKey(string key)
    {
        try
        {
            var sb = new StringBuilder("^");
            var last = 0;
            foreach (Match m in PlaceholderRe.Matches(key))
            {
                sb.Append(Regex.Escape(key[last..m.Index]));
                var name = m.Groups[1].Value;
                sb.Append("(?<").Append(name).Append('>').Append(PatternFor(name)).Append(')');
                last = m.Index + m.Length;
            }
            sb.Append(Regex.Escape(key[last..])).Append('$');
            return new Regex(sb.ToString(), RegexOptions.Compiled | RegexOptions.CultureInvariant);
        }
        catch (ArgumentException)
        {
            return null; // a key that doesn't compile (e.g. a name starting with a digit) is skipped
        }
    }

    private static string PatternFor(string name)
    {
        if (name.StartsWith("jp", StringComparison.Ordinal)) return ".+?";
        if (name == "dow") return "[日月火水木金土]";
        if (name.StartsWith("eng", StringComparison.Ordinal)) return ".+?";
        return "[0-9０-９]+";
    }

    // Returns null when a name placeholder can't be resolved, so the line is
    // treated as untranslated rather than shown half-filled.
    private string? Fill(string english, Match match)
    {
        var failed = false;
        var result = PlaceholderRe.Replace(english, m =>
        {
            var name = m.Groups[1].Value;

            if (name == "dow")
            {
                var g = match.Groups["dow"];
                return g.Success && WeekdayEn.TryGetValue(g.Value[0], out var d) ? d : m.Value;
            }

            if (name.StartsWith("eng", StringComparison.Ordinal))
            {
                var kind = name[3..];
                var g = match.Groups["jp" + kind];
                if (!g.Success) return m.Value;
                var resolved = ResolveName(kind, g.Value);
                if (resolved == null) { failed = true; return m.Value; }
                return resolved;
            }

            var cap = match.Groups[name];
            return cap.Success ? NormalizeDigits(cap.Value) : m.Value;
        });
        return failed ? null : result;
    }

    private string? ResolveName(string kind, string japanese)
    {
        switch (kind)
        {
            case "npcname":
                if (_deps.NpcNameDict().TryGetValue(japanese, out var npc) && !string.IsNullOrEmpty(npc)) return npc;
                return _deps.Romanizer.ToRomaji(japanese);
            case "playername":
                if (_deps.M00Dict("local_player_names").TryGetValue(japanese, out var player) && !string.IsNullOrEmpty(player)) return player;
                return _deps.Romanizer.ToRomaji(japanese);
            case "itemname":
                return _deps.M00Dict("items").TryGetValue(japanese, out var item) && !string.IsNullOrEmpty(item) ? item : null;
            case "monstername":
                return _deps.M00Dict("monsters").TryGetValue(japanese, out var monster) && !string.IsNullOrEmpty(monster) ? monster : null;
            default:
                return null;
        }
    }

    private static string NormalizeDigits(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s) sb.Append(c is >= '０' and <= '９' ? (char)('0' + (c - '０')) : c);
        return sb.ToString();
    }
}
