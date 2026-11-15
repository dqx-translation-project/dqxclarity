using System.Buffers.Binary;
using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// A casino-minigame player list -- opcode 0x4E, marker 0x7E96. Originally
// found via Bingo (hence the class name -- see the NAMING note below), but
// confirmed via two further live captures to also be what a Poker table
// sends: byte-for-byte the exact same header/record layout, right down to
// the same 68-byte stats width and the same length-prefixed name shape.
// Almost certainly shared by every casino minigame with a seated-player
// list (Slots, Roulette presumably included), not a Bingo-specific packet
// -- the opcode/marker and Build() logic need no per-game branching, since
// nothing about the layout is game-specific.
//
// Up to 16 players; the packet is variable-size because every player's own
// name can be a different length. Four sample captures on file now: two
// Bingo (3 players -- ショウブ/ぎんなん/カナレン; and 5 -- たける/ショウブ/
// りゅう/ぼあぼあ/マジタニ) and two Poker, captured back-to-back (16ms apart)
// while sitting down at a table: the first has 2 players (シルウィア, then
// ショウブ), the second has only 1 (ショウブ alone). ショウブ recurs across
// multiple captures, always at the exact same per-record byte offset
// (record offset 0x44) with the exact same 4-byte id (7D A9 18 01) leading
// that record every time, confirming records are located by walking forward
// sequentially rather than read at any fixed absolute offset.
//
// The two Poker captures support the user's hypothesis about how this
// packet is used at a table: the 1-player packet (just ショウブ, the locally
// logged-in character) looks like the initial "you sat down" send, and the
// very next packet (2 players, シルウィア now leading and ショウブ second)
// looks like the follow-up full-table update once an already-seated player
// is included. Not confirmed against a 3rd-party account to be certain it's
// specifically "your own name" rather than e.g. "first player to join,"
// but it's consistent with every capture on file so far.
//
// Layout, confirmed identical (down to the byte) across all four captures:
//   header   12 bytes -- passthrough. First u32 varies per capture (0, 1, 4,
//            5 seen so far -- maybe "your seat"/a highlight index, or a
//            session/tick counter, unconfirmed); second u32 was 0 in every
//            capture; third u32 is the player count, matching exactly how
//            many name fields each capture has (3, 5, 2, and 1).
//   record[0..count)  back to back, no gap, no padding after the last one --
//            in every capture every byte of the packet after the header is
//            consumed exactly by `count` records with nothing left over.
//
// Each record:
//   stats     fixed width per record (an id, bingo card numbers, running
//             totals, etc.), unexamined passthrough. 0x44 (68) bytes in the
//             original captures, 0x48 (72) since a game update -- see
//             StatsWidths below.
//   name_len  u32 -- the name's utf-8 byte length INCLUDING the null
//             terminator (the same length-prefixed shape EntityPacket uses
//             for Player/Party names and MonsterTavernListPacket uses for
//             monster nicknames). Confirmed exactly right for all 8 names
//             across both captures.
//   name      cstring (utf-8, null-terminated)
//
// Because each record announces its own name's length instead of living in
// a fixed-width slot, a translated name is free to grow or shrink -- same
// category as EntityPacket/MonsterTavernListPacket, not the fixed-offset
// "roster" family (TavernRecruitmentListPacket/AllianceMemberDetailPacket
// and friends) that has to truncate/zero-pad to avoid shifting anything
// after it. The name_len prefix is simply rewritten to the translated
// name's actual new byte count and every record downstream naturally lines
// up, because nothing reads any record at a fixed absolute offset -- each
// one is found by walking forward from the end of the previous one.
//
// The record boundaries are read precisely (known stats width + explicit
// length-prefixed cstring), not found via a whole-payload Japanese-run scan
// the way MonsterTavernListPacket has to -- so this isn't exposed to that
// class's documented punctuation-splitting failure mode (see
// AllianceMemberDetailPacket's doc comment for the bug that pattern hit
// elsewhere): a name containing embedded non-kana punctuation is still read
// as one atomic cstring here.
//
// Names are resolved the same way every other player name in this codebase
// is: m00 'local_player_names' dict first, romaji fallback when the name
// isn't in the dict.
//
// Samples: four live captures, opcode 0x4E marker 0x7E96 -- Bingo (3
// players, 5 players) and Poker (2 players, 1 player) -- no reference dump
// saved to docs/packets/references yet.
public sealed class CasinoPlayerListPacket : IPacket
{
    // Fixed per-record stats width, newest first. It was 68 bytes in the
    // original Bingo/Poker captures; a 2026-11-14 capture (7 players) has 72
    // -- a game update added 4 bytes to every record. The old code hard-coded
    // 68 and never checked it, so it read stats bytes as name lengths and
    // rewrote garbage all through the packet, crashing the game. Each width is
    // now tried in turn and only one that accounts for EVERY byte of the
    // packet (each name_len fits and ends on a null, nothing left over) is
    // used; if none fits, PacketLayoutException makes PacketGuard pass the
    // original through and file a mismatch report.
    private static readonly int[] StatsWidths = { 72, 68 };
    private const int HeaderBytes = 12;
    private const int MaxPlayers = 64;
    private const int MaxNameBytes = 256;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public CasinoPlayerListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < HeaderBytes)
            throw new PacketLayoutException($"only {_raw.Length} bytes, header needs {HeaderBytes}", 0);

        var count = BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(8, 4));
        if (count > MaxPlayers)
            throw new PacketLayoutException($"player count {count} at offset 8 is more than {MaxPlayers}", 8);

        List<(int LenAt, int NameAt, int NameLen, string Name)>? names = null;
        foreach (var width in StatsWidths)
        {
            names = TryParse((int)count, width);
            if (names != null) break;
        }
        if (names == null)
            throw new PacketLayoutException(
                $"{count} player records don't fit with any known stats width ({string.Join("/", StatsWidths)} bytes)", HeaderBytes);

        var dict = _deps.M00Dict("local_player_names");
        var writer = new PacketWriter();
        var pos = 0;
        var changed = false;
        foreach (var (lenAt, nameAt, nameLen, name) in names)
        {
            var newName = ResolveName(name, dict);
            if (newName == name) continue; // copied through below, untouched

            changed = true;
            writer.WriteBytes(_raw.AsSpan(pos, lenAt - pos)); // everything up to this name_len
            var bytes = Encoding.UTF8.GetBytes(newName);
            writer.WriteU32((uint)(bytes.Length + 1)); // +1 for the null terminator
            writer.WriteBytes(bytes);
            writer.WriteU8(0);
            pos = nameAt + nameLen + 1;
        }
        if (!changed) return;

        writer.WriteBytes(_raw.AsSpan(pos));
        ModifiedData = writer.Build();
    }

    // Walks `count` records of [stats][u32 name_len][name + null] with the given
    // stats width. Returns where each name sits, or null if the layout doesn't
    // fit the packet exactly.
    private List<(int LenAt, int NameAt, int NameLen, string Name)>? TryParse(int count, int statsWidth)
    {
        var result = new List<(int, int, int, string)>(count);
        var pos = HeaderBytes;
        for (var r = 0; r < count; r++)
        {
            pos += statsWidth;
            if (pos + 4 > _raw.Length) return null;

            var lenAt = pos;
            var len = BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(pos, 4));
            pos += 4;
            if (len < 1 || len > MaxNameBytes || len > (uint)(_raw.Length - pos)) return null;
            if (_raw[pos + (int)len - 1] != 0) return null;

            var nameBytes = _raw.AsSpan(pos, (int)len - 1);
            if (nameBytes.IndexOf((byte)0) >= 0) return null;
            if (!PacketText.TryDecode(nameBytes, out var name)) return null;

            result.Add((lenAt, pos, (int)len - 1, name));
            pos += (int)len;
        }
        return pos == _raw.Length ? result : null;
    }

    private string ResolveName(string japanese, Dictionary<string, string> dict)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        if (dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known)) return known;
        return _deps.Romanizer.ToRomaji(japanese);
    }
}
