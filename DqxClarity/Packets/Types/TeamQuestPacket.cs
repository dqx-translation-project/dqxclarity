namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   header_data   76 bytes (passthrough)
//   quest_1_name  cstring
//   quest_1_desc  cstring
//   quest_2_name  cstring
//   quest_2_desc  cstring
//
// Team quests always come in pairs. All four strings are looked up in m00
// 'custom_team_quests'; misses pass through as original japanese.
//
// The four strings are read strictly (each must be null-terminated text); a
// packet that doesn't fit makes PacketGuard pass the original through and file
// a mismatch report. Only strings that are actually translated are rewritten,
// anything after the fourth string is kept, and nothing is sent back when no
// string changed. (An earlier version rebuilt the packet on every arrival and
// dropped any bytes after the fourth string.)
//
// Sample: docs/packets/references/team_quest
public sealed class TeamQuestPacket : IPacket
{
    private const int HeaderBytes = 76;
    private const int MaxTextBytes = 2048;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public TeamQuestPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        var reader = new PacketReader(_raw);
        reader.ReadBytesStrict(HeaderBytes, "team quest header");

        var fields = new List<(int Start, int Length, string Text)>();
        foreach (var what in new[] { "quest 1 name", "quest 1 description", "quest 2 name", "quest 2 description" })
        {
            var start = reader.Position;
            var text = reader.ReadCStringStrict(what, MaxTextBytes);
            fields.Add((start, reader.Position - 1 - start, text));
        }
        // Anything after the fourth string is left exactly as it is.

        var dict = _deps.M00Dict("custom_team_quests");
        var patch = new PacketPatch(_raw);
        foreach (var (start, length, text) in fields)
        {
            if (text.Length == 0) continue;
            if (!dict.TryGetValue(text, out var en) || string.IsNullOrEmpty(en) || en == text) continue;
            patch.ReplaceText(start, length, en);
        }

        if (patch.HasEdits) ModifiedData = patch.Build();
    }
}
