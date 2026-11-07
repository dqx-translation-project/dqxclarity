using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// One line of an equipment piece's item history -- the player name shown for
// who crafted it or who enchanted it. Opcode 0x8E, marker 0xEE25. (Same
// 0xEE25 marker as EntityPacket (0x52) and Chat_Party (0x0d), different
// opcode -- the marker alone isn't unique, only the (opcode, marker) pair
// is.) One packet is sent per history line; the first u32 below counts them
// (0, 1, 2 across the three captures on file).
//
// The server also sends this same name lookup in a batched form -- several
// names in one packet -- under marker 0x732B; see ItemHistoryNameListPacket.
// Which form it picks isn't understood; both occur in live play.
//
// Layout (after opcode + marker), confirmed identical across all three
// captures:
//   index        u32 -- 0, 1, 2 in the three captures, i.e. which history
//                line this is. Passthrough.
//   zero         u32 -- 0 in every capture. Passthrough.
//   id           u32 -- differs per capture (110973419, 341620884,
//                565853974) and doesn't track the name's length in any way
//                (checked), so it's not a length prefix. It's the player's
//                id: the same ids show up in ItemHistoryNameListPacket
//                (0x8E / 0x732B), which carries them alongside the names.
//                Passthrough.
//   player_name  cstring (utf-8, null-terminated, no length prefix)
//   (nothing follows the terminator in any capture)
//
// Unlike the fixed-total-size notification packets in this codebase
// (TeamJoinMessagePacket, FriendRequestAcceptedPacket,
// HiredMemberExpirationPacket -- same name-length-independent total size no
// matter whose name it carries), this packet's total size follows the name
// exactly: 22, 28 and 31 bytes of Data for names of 9, 15 and 18 utf-8
// bytes, which is always 12 + name + terminator. The name is also the very
// last field, so nothing positioned after it can shift. That's the same
// shape as MailMessagePacket's / QuestAcceptDialoguePacket's trailing text,
// so the translated name is simply written back at its new length rather
// than pinned to the original byte width. NOT crash-tested against a live
// capture yet -- if a translated name here ever crashes or corrupts the
// client, this needs the fixed-width-slot treatment FriendRequestAccepted-
// Packet uses instead (original name's byte width + 1, truncate/zero-pad).
//
// player_name is a player-chosen character name, so it's resolved like every
// other player name in this codebase: m00 'local_player_names' first, romaji
// fallback on a miss. No \x04 prefix -- that's an EntityPacket nameplate
// trick, not a general player-name convention.
//
// Samples: docs/packets/references/item_history_name_1 (アリス, index 0),
//          docs/packets/references/item_history_name_2 (アンドレア, index 1),
//          docs/packets/references/item_history_name_3 (まっちゃもち, index 2)
public sealed class ItemHistoryNamePacket : IPacket
{
    private const int HeaderBytes = 12;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _playerName = "";
    private byte[] _remainder = Array.Empty<byte>();
    private bool _parsed;

    public byte[]? ModifiedData { get; private set; }

    public ItemHistoryNamePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes + 1) return;
        var reader = new PacketReader(_raw);
        _header     = reader.ReadBytes(HeaderBytes).ToArray();
        _playerName = reader.ReadCString();
        _remainder  = reader.RemainingBytes().ToArray();
        _parsed = true;
    }

    public void Build()
    {
        if (!_parsed) return;

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
