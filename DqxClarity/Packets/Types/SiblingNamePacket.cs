using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The player's sibling's name, used in story cutscenes/dialogue involving
// them. Opcode 0x5c/marker 0x0bf6 -- a small, one-off packet (not a list),
// only one capture on file (46 bytes of Data).
//
// Layout (after opcode + marker):
//   header    36 bytes (passthrough, unexamined beyond noting what it
//             likely carries: two IEEE-754 floats at Data offset 0x1C/0x20
//             decode to plausible in-world coordinates (-67.35, -22.59),
//             probably the sibling's position for whatever scene this
//             fires in; also a couple of small ids/flags -- u32=1925 at
//             0x08, u32=1 at 0x0C, u32=9061 at 0x10 -- whose meaning is
//             unconfirmed)
//   name      cstring (utf-8, null-terminated) -- the LAST field in the
//             packet, nothing follows it
//
// Because the name is the trailing field with nothing after it that a
// length change could shift, this is safe to let grow or shrink freely --
// same category as NpcDialoguePacket/MailMessagePacket/ImportantNoticePacket,
// not the fixed-offset roster family (see those packets' doc comments for
// the crash class this sidesteps by not needing the fixed-width-slot fix).
// GamePacket's outer wire-frame resize handles the length change.
//
// Resolved the same way every other player-chosen name in this codebase
// is: m00 'local_player_names' dict first, romaji fallback on miss -- the
// sibling's name is set at character creation like the player's own, so
// it's treated the same rather than as curated NPC dialogue.
//
// Sample: docs/packets/references/sibling_name (カッタ)
public sealed class SiblingNamePacket : IPacket
{
    private const int HeaderBytes = 36;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _name = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public SiblingNamePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes) return;
        var reader = new PacketReader(_raw);
        _header = reader.ReadBytes(HeaderBytes).ToArray();
        _name = reader.ReadCString();
        _remainder = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var newName = ResolveName(_name);
        if (newName == _name) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(newName);
        writer.WriteBytes(_remainder);
        ModifiedData = writer.Build();
    }

    private string ResolveName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        var dict = _deps.M00Dict("local_player_names");
        if (dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known)) return known;
        return _deps.Romanizer.ToRomaji(japanese);
    }
}
