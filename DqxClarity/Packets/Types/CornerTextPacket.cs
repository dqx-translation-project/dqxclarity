using System.Text;

namespace DqxClarity.Packets.Types;

// The top-right "corner text" hint/status shown during certain minigame-like
// events, and also (same packet shape/marker) combat "chat" lines -- boss
// taunts and party battle-cry lines shown in the same corner during fights.
// The original two captures line up with entries in custom_corner_text.json
// (a "push the pedal, thread right" instruction and a "ran out of time,
// failed" status line — matches the thread-and-pedal sequence minigame);
// combat lines instead live in custom_combat_chat.json.
//
// Layout (after opcode + marker):
//   header        12 bytes (passthrough — Data[0:4] looks like an
//                 incrementing per-message sequence index (0, then 1 across
//                 the two captures); Data[4:8] was 0 in both; Data[8:12]
//                 (193, then 204) doesn't match any other field and isn't
//                 needed to translate the text, so it's left opaque too)
//   text_length   u32 (utf-8 byte length of the text INCLUDING the null
//                 terminator — confirmed an exact match in both captures,
//                 so unlike TowerAnswerPacket/MailMessagePacket this field
//                 IS load-bearing and gets recomputed on write)
//   text          cstring (utf-8, null-terminated)
//   tail          4 bytes (passthrough — "00 00 00 00" in both captures)
//
// Looked up verbatim in m00 'custom_corner_text' then 'custom_combat_chat'
// (first hit wins); misses pass through as the original Japanese — NOT
// machine translated, same handling as custom_mail: both sources are fixed,
// curated sets (292 + 175 entries), not freeform prose, so a miss shouldn't
// get MT'd into something the curators didn't sign off on. Both files are
// ingested automatically by TranslationUpdater's generic /json/*.json ->
// m00_strings routing (each entry there is `{ id: { ja: en } }`, which the
// importer already unwraps) — no updater changes needed for either.
//
// Samples: docs/packets/references/corner_text,
//          docs/packets/references/corner_text_2 (confirms header/length
//          field layout across two different messages)
public sealed class CornerTextPacket : IPacket
{
    private const int HeaderBytes = 12;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _text = "";
    private byte[] _tail = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public CornerTextPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes + 4) return;
        var reader = new PacketReader(_raw);
        _header = reader.ReadBytes(HeaderBytes).ToArray();
        _ = reader.ReadU32(); // text_length — recomputed on write
        _text = reader.ReadCString();
        _tail = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var dict = _deps.M00Dict("custom_corner_text", "custom_combat_chat");
        if (!dict.TryGetValue(_text, out var newText) || string.IsNullOrEmpty(newText)) return;
        if (newText == _text) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        var bytes = Encoding.UTF8.GetBytes(newText);
        writer.WriteU32((uint)(bytes.Length + 1)); // include null terminator in length
        writer.WriteCString(newText);
        writer.WriteBytes(_tail);

        ModifiedData = writer.Build();
    }
}
