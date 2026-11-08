using System.Buffers.Binary;
using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The batched form of the equipment item-history name lookup -- opcode 0x8E,
// marker 0x732B. Same player names as ItemHistoryNamePacket (0x8E / 0xEE25,
// one name per packet), but this one carries several names in a single
// packet, so its total length varies with how many names it holds. The
// server seems to answer the same lookup with either form with no pattern
// anyone's found yet -- the player ids line up across both (0x145CB894 is
// アンドレア and 0x21BA3F16 is まっちゃもち in this packet's first capture, the
// same two ids ItemHistoryNamePacket's samples carry in its id field), so
// the two are almost certainly two reply shapes for the same query.
//
// Layout (after opcode + marker), decoded from three captures:
//   kind     u32 -- 3, 3 and 5 in the captures. Passthrough, meaning unknown.
//   zero     u32 -- 0 in every capture. Passthrough.
//   count    u32 -- N, the number of names (2, 2 and 1).
//   ids      N x u32 -- player ids, in the same order as the names below.
//            Passthrough.
//   count    u32 -- N again (verified equal in all three captures).
//   slots    N x 36 bytes -- each a null-terminated utf-8 name followed by
//            whatever was left in the buffer: a fixed 36-byte buffer, not
//            exactly sized to the name. The bytes after the terminator are
//            stale junk (ASCII fragments, binary, ints) that differs per
//            capture and means nothing -- passthrough, never touched.
//   Total Data length is 16 + 40N (96 bytes for N = 2, 56 for N = 1) in
//   every capture, which is what pins the 36-byte slot width.
//
// Because the slots are a fixed width, this is the pinned-width family
// (TeamJoinMessagePacket etc.), not the grow/shrink family: a translated name
// is written into its slot, zero-padded over the old name, and truncated
// (on a utf-8 character boundary) if it won't fit in 35 bytes + terminator.
// The packet's total length never changes and nothing after a slot shifts.
// Only the old name's bytes and the terminator are cleared; the stale tail
// after them is left exactly as received.
//
// Names resolve like every other player name in this codebase: m00
// 'local_player_names' first, romaji fallback on a miss. No \x04 prefix --
// that's an EntityPacket nameplate trick, not a general player-name
// convention.
//
// NOT tested in-game yet. If this ever crashes the client (the slime-name
// packets did, with provably correct fixed-width slots, so a correct layout
// isn't proof of safety), disable Build() the same way
// SlimeRaceNameListPacket was.
//
// Samples: docs/packets/references/item_history_name_list_1 (2 names:
//          アンドレア, まっちゃもち, kind 3),
//          docs/packets/references/item_history_name_list_2 (2 names:
//          こいけ, メタりん, kind 3),
//          docs/packets/references/item_history_name_list_3 (1 name:
//          ルシュカ, kind 5)
public sealed class ItemHistoryNameListPacket : IPacket
{
    private const int SlotBytes = 36;
    private const int MaxCount = 32; // sanity bound; captures show 1-2

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public ItemHistoryNameListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < 16) return;

        var count = BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(8, 4));
        if (count == 0 || count > MaxCount) return;

        var n = (int)count;
        var slotsStart = 12 + 4 * n + 4;
        if (_raw.Length < slotsStart + SlotBytes * n) return;

        // The count is repeated right before the slots; if it isn't, this
        // isn't the shape we decoded -- leave it alone.
        if (BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(slotsStart - 4, 4)) != count) return;

        var data = (byte[])_raw.Clone();
        var changed = false;

        for (var i = 0; i < n; i++)
        {
            var slot = slotsStart + i * SlotBytes;
            var term = Array.IndexOf(data, (byte)0, slot, SlotBytes);
            if (term <= slot) continue; // empty or unterminated slot

            var oldLen = term - slot;
            var name = Encoding.UTF8.GetString(data, slot, oldLen);
            var resolved = ResolveName(name);
            if (resolved == name) continue;

            var bytes = TruncateUtf8(Encoding.UTF8.GetBytes(resolved), SlotBytes - 1);

            // Clear the old name + terminator, or the new name + terminator,
            // whichever is longer, so a shorter replacement doesn't leave
            // the tail of the old name behind it. Everything past that is
            // the slot's stale buffer and is left alone.
            var clearLen = Math.Max(oldLen + 1, bytes.Length + 1);
            Array.Clear(data, slot, clearLen);
            Buffer.BlockCopy(bytes, 0, data, slot, bytes.Length);
            changed = true;
        }

        if (changed) ModifiedData = data;
    }

    private string ResolveName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;

        var playerDict = _deps.M00Dict("local_player_names");
        if (playerDict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known)) return known;

        return _deps.Romanizer.ToRomaji(japanese);
    }

    // Cuts to at most `max` bytes without splitting a utf-8 sequence.
    private static byte[] TruncateUtf8(byte[] bytes, int max)
    {
        if (bytes.Length <= max) return bytes;
        var cut = max;
        while (cut > 0 && (bytes[cut] & 0xC0) == 0x80) cut--;
        return bytes[..cut];
    }
}
