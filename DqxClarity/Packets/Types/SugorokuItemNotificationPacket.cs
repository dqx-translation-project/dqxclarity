using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// Sugoroku (the board-game minigame)'s "you won an item" notification --
// opcode 0x95, marker 0xC9E3. Fired once per item won at the end of a
// Sugoroku game, naming both the winning player and the item they got.
//
// Layout, confirmed identical (down to the byte, including that both fields'
// length prefixes exactly match their cstring's real length) in both sample
// captures:
//   header           12 bytes -- passthrough. First u32 differs between
//                    captures (10 vs 14 -- unconfirmed, maybe a roll/turn
//                    counter); second u32 was 0 in both; third u32 was
//                    IDENTICALLY 0x151 (337) in both captures despite the
//                    two items being completely different ("幻界闘士の
//                    ゆびわ" vs "ドット風エステラ像") -- too consistent to
//                    be an item id, more likely a constant tagging this as
//                    a "Sugoroku item win" notification. Unconfirmed either
//                    way; passed through untouched regardless.
//   player_name_len  u32 -- the player name's utf-8 byte length INCLUDING
//                    the null terminator (the same length-prefixed shape
//                    EntityPacket/MonsterTavernListPacket/
//                    BingoPlayerListPacket use elsewhere).
//   player_name      cstring (utf-8, null-terminated)
//   item_name_len    u32 -- same shape, for the item name
//   item_name        cstring (utf-8, null-terminated) -- the LAST field,
//                    nothing follows it in either capture
//
// Both names are length-prefixed rather than living in a fixed-width slot,
// so a translated name is free to grow or shrink -- same category as
// EntityPacket/MonsterTavernListPacket/BingoPlayerListPacket, not the
// fixed-offset "roster" family that has to truncate/zero-pad to avoid
// shifting anything after it.
//
// Translation:
//   player_name : resolved the same way every other player name in this
//                 codebase is -- m00 'local_player_names' dict first, romaji
//                 fallback when the name isn't in the dict.
//   item_name   : per the user, looked up in the m00 'items' category only,
//                 with NO romaji fallback -- a miss passes through as the
//                 original Japanese untouched, same policy QuestPacket's
//                 reward fields use for item lookups that miss (romanizing
//                 an item name would just produce meaningless kana-to-latin
//                 noise, not an actual English name).
//
// Samples: two live captures, opcode 0x95 marker 0xC9E3, player トギ winning
// 幻界闘士のゆびわ and ドット風エステラ像 -- no reference dump saved to
// docs/packets/references yet.
public sealed class SugorokuItemNotificationPacket : IPacket
{
    private const int HeaderBytes = 12;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public SugorokuItemNotificationPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < HeaderBytes) return;

        var reader = new PacketReader(_raw);
        var header = reader.ReadBytes(HeaderBytes).ToArray();

        if (reader.Remaining < 4) return;
        _ = reader.ReadU32(); // player_name_len -- recomputed on write
        var playerName = reader.ReadCString();

        if (reader.Remaining < 4) return;
        _ = reader.ReadU32(); // item_name_len -- recomputed on write
        var itemName = reader.ReadCString();

        // Nothing follows the item name in either sample, but don't
        // silently drop anything if a future capture has a trailer.
        var remainder = reader.RemainingBytes().ToArray();

        var newPlayerName = ResolvePlayerName(playerName);
        var newItemName = ResolveItemName(itemName);

        if (newPlayerName == playerName && newItemName == itemName) return;

        var writer = new PacketWriter();
        writer.WriteBytes(header);

        var playerBytes = Encoding.UTF8.GetBytes(newPlayerName);
        writer.WriteU32((uint)(playerBytes.Length + 1)); // +1 for null terminator
        writer.WriteCString(newPlayerName);

        var itemBytes = Encoding.UTF8.GetBytes(newItemName);
        writer.WriteU32((uint)(itemBytes.Length + 1)); // +1 for null terminator
        writer.WriteCString(newItemName);

        writer.WriteBytes(remainder);
        ModifiedData = writer.Build();
    }

    private string ResolvePlayerName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        var dict = _deps.M00Dict("local_player_names");
        if (dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known)) return known;
        return _deps.Romanizer.ToRomaji(japanese);
    }

    // No romaji fallback -- a miss passes through as the original Japanese
    // untouched, same as every other item-name lookup in this codebase.
    private string ResolveItemName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        var dict = _deps.M00Dict("items");
        return dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known) ? known : japanese;
    }
}
