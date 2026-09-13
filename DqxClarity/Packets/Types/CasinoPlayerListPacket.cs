using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// A casino-minigame player list -- opcode 0x4E, marker 0x7E96. Originally
// found via Bingo (hence the class was first named BingoPlayerListPacket --
// see the NAMING note below), but confirmed via two further live captures to
// also be what a Poker table sends: byte-for-byte the exact same header/
// record layout, right down to
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
// NAMING: renamed from BingoPlayerListPacket to CasinoPlayerListPacket once
// the Poker captures confirmed this isn't Bingo-specific -- nothing about
// the implementation ever was, it's just where the packet was first found.
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
//   stats     0x44 (68) bytes -- confirmed the SAME fixed width in every
//             record of both captures regardless of that record's own name
//             length (an id, bingo card numbers, running totals, etc.).
//             Unexamined, passthrough.
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
    private const int StatsBytes = 0x44; // 68

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
        if (_raw.Length < 12) return;

        var reader = new PacketReader(_raw);
        var header = reader.ReadBytes(8).ToArray(); // two leading u32s -- passthrough, meaning unconfirmed
        var count = reader.ReadU32();

        var dict = _deps.M00Dict("local_player_names");
        var changed = false;
        var writer = new PacketWriter();
        writer.WriteBytes(header);
        writer.WriteU32(count);

        for (var r = 0; r < count; r++)
        {
            // Not enough data left for a full record -- stop and pass
            // through whatever remains untouched rather than risk reading
            // past the end of a malformed/short capture.
            if (reader.Remaining < StatsBytes + 4) break;

            var stats = reader.ReadBytes(StatsBytes).ToArray();
            _ = reader.ReadU32(); // name_len -- recomputed on write
            var name = reader.ReadCString();

            var newName = ResolveName(name, dict);
            if (newName != name) changed = true;

            writer.WriteBytes(stats);
            var newBytes = Encoding.UTF8.GetBytes(newName);
            writer.WriteU32((uint)(newBytes.Length + 1)); // +1 for null terminator
            writer.WriteCString(newName);
        }

        // Anything left over (shouldn't happen -- both samples' records
        // consumed the packet exactly) -- don't silently drop it.
        writer.WriteBytes(reader.RemainingBytes().ToArray());

        if (!changed) return;
        ModifiedData = writer.Build();
    }

    private string ResolveName(string japanese, Dictionary<string, string> dict)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        if (dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known)) return known;
        return _deps.Romanizer.ToRomaji(japanese);
    }
}
