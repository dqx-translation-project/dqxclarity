using System.Text;

namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   header_data         52 bytes (passthrough)
//   quest_name          cstring
//   quest_objective_1   cstring
//   quest_objective_2   cstring  (optional, repeats)
//   ...
//
// All strings are looked up in m00 'custom_master_quests'; misses pass through.
//
// Everything after the header is walked as null-terminated segments IN PLACE:
// only segments that are valid text and actually get translated are replaced,
// and every other byte -- empty strings, runs of nulls, anything that isn't
// text, an unterminated tail -- stays exactly where it was. (An earlier version
// split the whole tail on nulls and re-emitted the strings followed by all the
// empty ones, which moved any empty string sitting between two others to the
// end, and it rebuilt the packet even when nothing was translated.)
//
// The quest NAME (not the objectives) is capped at 34 UTF-8 bytes PER LINE --
// per the user, this is a real client-side UI limitation, but only for
// rendering English text, and it applies to a single line of the name: when
// the name contains a newline, each line is capped on its own (neither line
// of a two-line name ever reaches the limit), so the cap is applied line by
// line rather than to the whole string. The original code applied the cap unconditionally,
// including when the dict had no translation and the original Japanese was
// passed through untouched -- that's wrong on two counts: Japanese doesn't
// have this limitation (a 71-byte untranslated capture renders fine, since
// that's literally what the live server already sends), and character-by-
// character truncation on multi-byte Japanese text chops the name mid-word
// with no ellipsis or indication anything was cut. Fixed by only applying
// TruncateUtf8 when an actual translation was found in the dict.
//
// The name lookup also tolerates a missing trailing newline in the dictionary
// key -- see ResolveQuestName.
//
// Sample: docs/packets/references/master_quest_untranslated (the 71-byte
//         untranslated name -- 踊り子と行く！\n　迅速な魔人エンラージャ強討伐！\n --
//         that exposed the truncation bug: byte 34 lands right after な,
//         chopping off everything from 魔人エンラージャ強討伐！ onward)
public sealed class MasterQuestPacket : IPacket
{
    private const int HeaderBytes = 52;
    private const int MaxNameBytesPerLine = 34;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MasterQuestPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < HeaderBytes) return; // locked / empty entry: nothing to translate

        // Null-terminated text segments after the header, in order.
        var segments = new List<(int Start, int Length, string Text)>();
        var pos = HeaderBytes;
        while (pos < _raw.Length)
        {
            var nul = Array.IndexOf(_raw, (byte)0, pos);
            if (nul < 0) break; // unterminated tail: leave it alone
            var len = nul - pos;
            if (len > 0 && PacketText.TryDecode(_raw.AsSpan(pos, len), out var text, allowLineBreaks: true))
                segments.Add((pos, len, text));
            pos = nul + 1;
        }
        if (segments.Count == 0) return;

        var dict = _deps.M00Dict("custom_master_quests");
        var patch = new PacketPatch(_raw);

        // First string is the quest name; the rest are objectives.
        var (nameStart, nameLength, name) = segments[0];
        var resolvedName = ResolveQuestName(dict, name);
        if (resolvedName != name && !string.IsNullOrEmpty(resolvedName))
            patch.ReplaceText(nameStart, nameLength, TruncatePerLine(resolvedName, MaxNameBytesPerLine));

        foreach (var (start, length, objective) in segments.Skip(1))
        {
            if (!dict.TryGetValue(objective, out var en) || string.IsNullOrEmpty(en) || en == objective) continue;
            patch.ReplaceText(start, length, en);
        }

        if (patch.HasEdits) ModifiedData = patch.Build();
    }

    private static string ResolveQuestName(Dictionary<string, string> dict, string name)
    {
        if (dict.TryGetValue(name, out var exact) && !string.IsNullOrEmpty(exact)) return exact;
        var trimmed = name.TrimEnd('\n');
        if (trimmed.Length == name.Length || trimmed.Length == 0) return name;
        if (!dict.TryGetValue(trimmed, out var found) || string.IsNullOrEmpty(found)) return name;
        var suffix = name[trimmed.Length..];
        return found.EndsWith('\n') ? found : found + suffix;
    }

    private static string TruncatePerLine(string s, int maxBytesPerLine) =>
        string.Join("\n", s.Split('\n').Select(line => PacketPatch.TruncateUtf8(line, maxBytesPerLine)));
}
