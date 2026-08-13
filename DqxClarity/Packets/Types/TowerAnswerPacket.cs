namespace DqxClarity.Packets.Types;

// Sent when the game shows the result/confirmation line after you complete a
// "Tower" quiz answer (e.g. Slime Tower-style trivia: "スライムを　メラで倒した。"
// -> "Defeat a Slime using Frizz."). One string per packet, no length prefix.
//
// Layout (after opcode + marker):
//   header_data   24 bytes (passthrough — offset 8 is a 1-byte value that
//                 changes per answer (0x1E vs 0x34 across two captures) and
//                 is likely a question/answer id; offset 16-19 ("60 DF 1E 01")
//                 held constant across two captures 16 minutes apart, but a
//                 MailboxLetterPacket capture (unrelated feature) shows the
//                 same-shaped field at a different offset changing by ~8.5M
//                 over a ~2.5 hour gap — so this is a monotonic tick/counter
//                 (client uptime or a server tick), not a static constant;
//                 it just doesn't move much over a few minutes. Neither
//                 field is confirmed enough to parse meaningfully, so both
//                 stay opaque.)
//   answer_text   cstring (utf-8, null-terminated; NOT length-prefixed like
//                 EntityPacket/NpcDialoguePacket — this packet only has the
//                 24-byte header immediately before the string)
//   remaining     (passthrough — expected empty; captured defensively in
//                 case a variant carries trailing bytes)
//
// The string is looked up verbatim (trailing newline(s) included exactly as
// they appear on the wire — one capture had "\n\n", another just "\n") in
// m00 'custom_tower_answers'; misses pass through as original japanese. That
// file is ingested automatically by TranslationUpdater's generic
// /json/*.json -> m00_strings routing (file tag = filename without
// extension), so no updater changes are needed for this dictionary to load.
//
// Samples: docs/packets/references/tower_answer,
//          docs/packets/references/tower_answer_2
public sealed class TowerAnswerPacket : IPacket
{
    private const int HeaderBytes = 24;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _text = "";
    private byte[] _remaining = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public TowerAnswerPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes) return;
        var reader = new PacketReader(_raw);
        _header    = reader.ReadBytes(HeaderBytes).ToArray();
        _text      = reader.ReadCString();
        _remaining = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var dict = _deps.M00Dict("custom_tower_answers");
        if (!dict.TryGetValue(_text, out var newText) || string.IsNullOrEmpty(newText)) return;
        if (newText == _text) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(newText);
        writer.WriteBytes(_remaining);

        ModifiedData = writer.Build();
    }
}
