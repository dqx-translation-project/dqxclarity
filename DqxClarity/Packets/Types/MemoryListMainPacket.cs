using System.Text;

namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   header_data  12 bytes (passthrough)
//   text_list    null-separated utf-8 strings, all concatenated
//
// Each string is looked up in m00 'story_names'; misses pass through. Translated
// strings are capped at 29 utf-8 bytes — the game's memory window locks up otherwise.
//
// Strings are replaced IN PLACE: only ones that are valid text and actually
// get translated are rewritten, and every other byte (empty strings, runs of
// nulls, an unterminated tail) stays exactly where it was. Nothing is sent
// back when nothing was translated. (An earlier version rebuilt the packet on
// every arrival, cut EVERY string to 29 bytes -- untranslated Japanese titles
// included -- and collapsed empty strings, so it changed the packet even with
// nothing to translate.)
public sealed class MemoryListMainPacket : IPacket
{
    private const int HeaderBytes = 12;
    private const int MaxChapterBytes = 29;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MemoryListMainPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < HeaderBytes) return;

        var dict = _deps.M00Dict("story_names");
        var patch = new PacketPatch(_raw);
        var pos = HeaderBytes;
        while (pos < _raw.Length)
        {
            var nul = Array.IndexOf(_raw, (byte)0, pos);
            if (nul < 0) break; // unterminated tail: leave it alone
            var len = nul - pos;
            if (len > 0
                && PacketText.TryDecode(_raw.AsSpan(pos, len), out var text, allowLineBreaks: true)
                && dict.TryGetValue(text, out var en) && !string.IsNullOrEmpty(en) && en != text)
            {
                patch.ReplaceText(pos, len, PacketPatch.TruncateUtf8(en, MaxChapterBytes));
            }
            pos = nul + 1;
        }

        if (patch.HasEdits) ModifiedData = patch.Build();
    }
}
