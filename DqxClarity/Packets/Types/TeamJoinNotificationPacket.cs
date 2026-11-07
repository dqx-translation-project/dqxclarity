using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The "<player> joined the Team!" broadcast. The player name sits right up
// front, everything else is opaque — a large (~1780-byte) trailing blob
// that includes what looks like embedded pointer-shaped values (repeating
// 4-byte patterns like "20 34 A5 0C") and unrelated ASCII text (a Discord
// invite string), none of which this touches.
//
// Layout (after opcode + marker):
//   header        12 bytes (passthrough — mostly zero, ends in a 4-byte id
//                 that reappears verbatim at Data offset 1060 deep in the
//                 untouched remainder, so it's cross-referencing something
//                 elsewhere in the packet rather than describing the name
//                 field itself)
//   player_name   cstring (utf-8, null-terminated, no length prefix)
//   remainder     rest of payload (passthrough, ~1780 bytes, unexamined)
//
// Resolved the same way EntityPacket resolves a Player entity's name:
// 'local_player_names' m00 dict first, romaji fallback on miss. No \x04
// prefix like EntityPacket's Player/Party cases use — that prefix exists
// to stop the game drawing a GM-face icon / to guard against EntityPacket
// re-intercepting its own write on the next tick's entity broadcast, and
// neither rationale obviously applies to a one-shot text notification, so
// it's omitted unless a capture shows the notification rendering wrong.
// IsTextJapanese still guards against re-processing generally.
//
// On packet-size handling: this does NOT need to keep the translated name
// byte-length equal to the original's. GamePacket.ParseData already
// recalculates the outer wire-frame size header (RecalculateSize) whenever
// DataPacketRouter returns ModifiedData of a different length than the
// original payload -- every other packet type in this router already
// relies on exactly this (NpcDialoguePacket, EntityPacket, etc. all freely
// grow/shrink text on translation), so nothing extra is needed here either.
// The one caveat: this packet's ~1780-byte remainder is completely
// unexamined, so I can't rule out some deeper part of that blob assuming a
// fixed byte offset for whatever comes after the name. Only one capture
// was available (name = "しろ", short); if you can grab a second capture
// with a longer romanized name in play and confirm the notification still
// renders correctly, that would close out the one open question here.
//
// Sample: docs/packets/references/team_join_notification
public sealed class TeamJoinNotificationPacket : IPacket
{
    private const int HeaderBytes = 12;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _playerName = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public TeamJoinNotificationPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes) return;
        var reader = new PacketReader(_raw);
        _header     = reader.ReadBytes(HeaderBytes).ToArray();
        _playerName = reader.ReadCString();
        _remainder  = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var newName = ResolveName(_playerName);
        if (newName == _playerName) return;

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
