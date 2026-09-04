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
// Trailing nulls between strings are preserved verbatim to keep packet structure
// identical for unmapped users.
//
// The quest NAME (not the objectives) is capped at 34 UTF-8 bytes -- per
// the user, this is a real client-side UI limitation, but only for
// rendering English text. The original code applied the cap unconditionally,
// including when the dict had no translation and the original Japanese was
// passed through untouched -- that's wrong on two counts: Japanese doesn't
// have this limitation (a 71-byte untranslated capture renders fine, since
// that's literally what the live server already sends), and character-by-
// character truncation on multi-byte Japanese text chops the name mid-word
// with no ellipsis or indication anything was cut. Fixed by only applying
// TruncateUtf8 when an actual translation was found in the dict.
//
// Sample: docs/packets/references/master_quest_untranslated (the 71-byte
//         untranslated name -- 踊り子と行く！\n　迅速な魔人エンラージャ強討伐！\n --
//         that exposed the truncation bug: byte 34 lands right after な,
//         chopping off everything from 魔人エンラージャ強討伐！ onward)
public sealed class MasterQuestPacket : IPacket
{
    private const int HeaderBytes = 52;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _questName = "";
    private readonly List<string> _objectives = new();
    private int _trailingNulls;
    private bool _unlocked;

    public byte[]? ModifiedData { get; private set; }

    public MasterQuestPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes)
        {
            _unlocked = false;
            return;
        }

        _header = _raw.AsSpan(0, HeaderBytes).ToArray();
        var rest = _raw.AsSpan(HeaderBytes).ToArray();

        // Split on \x00, count empty entries as the trailing-null count and drop them.
        // The very last string in the buffer was null-terminated too, so subtract one if we found any.
        var splits = SplitNull(rest);
        var nullCount = splits.Count(s => s.Length == 0);
        if (nullCount > 0) nullCount -= 1;
        _trailingNulls = nullCount;

        var strings = splits.Where(s => s.Length > 0)
                            .Select(b => Encoding.UTF8.GetString(b))
                            .ToList();

        if (strings.Count == 0) { _unlocked = false; return; }

        _unlocked = true;
        _questName = strings[0];
        _objectives.AddRange(strings.Skip(1));
    }

    public void Build()
    {
        if (!_unlocked) return;

        var dict = _deps.M00Dict("custom_master_quests");

        var writer = new PacketWriter();
        writer.WriteBytes(_header);

        // Only cap when an actual translation was applied -- the 34-byte
        // limit is a UI constraint for rendering English text, it doesn't
        // apply to the original Japanese (see class doc comment).
        var resolvedName = dict.GetValueOrDefault(_questName, _questName);
        var name = resolvedName == _questName ? resolvedName : TruncateUtf8(resolvedName, 34);
        writer.WriteCString(name);
        foreach (var obj in _objectives)
            writer.WriteCString(dict.GetValueOrDefault(obj, obj));

        if (_trailingNulls > 0) writer.WriteBytes(new byte[_trailingNulls]);

        ModifiedData = writer.Build();
    }

    private static List<byte[]> SplitNull(byte[] data)
    {
        var parts = new List<byte[]>();
        var start = 0;
        for (var i = 0; i < data.Length; i++)
        {
            if (data[i] == 0)
            {
                parts.Add(data.AsSpan(start, i - start).ToArray());
                start = i + 1;
            }
        }
        if (start <= data.Length) parts.Add(data.AsSpan(start).ToArray());
        return parts;
    }

    private static string TruncateUtf8(string s, int maxBytes)
    {
        var bytes = Encoding.UTF8.GetByteCount(s);
        if (bytes <= maxBytes) return s;
        var sb = new StringBuilder();
        var running = 0;
        foreach (var c in s)
        {
            var cb = Encoding.UTF8.GetByteCount(new[] { c });
            if (running + cb > maxBytes) break;
            sb.Append(c);
            running += cb;
        }
        return sb.ToString();
    }
}
