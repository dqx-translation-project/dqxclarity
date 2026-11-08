using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// TRANSLATION CURRENTLY DISABLED -- CONFIRMED CRASH. A live 0x69CA capture
// (3 names: ドレイク, カンカン, バイト, all translated via the fixed-width-slot
// approach below) crashed the DQX client. Re-simulating the exact Build()
// logic against the user's "before" bytes reproduces their "after" bytes
// byte-for-byte -- same 191-byte total length, every byte outside the three
// name slots at the identical offset in both -- so this is NOT the usual
// "translation changed length/shifted something downstream" crash this
// codebase has hit before (TeamJoinMessagePacket and friends). Whatever's
// wrong is about the CONTENT landing in these fields, not their position or
// width. Leading theory, unconfirmed: this UI (and/or the slime-naming
// screens generally) may render through a path that assumes kana-only
// text, unlike player-name fields elsewhere in this codebase (Friend-
// RequestAcceptedPacket, HiredMemberExpirationPacket) which use the exact
// same fixed-width-slot mechanics with romaji and are NOT known to crash.
// Until the real mechanism is confirmed, Build() below is a deliberate
// no-op (see its own comment) -- names are parsed/routed correctly but
// never rewritten, so every marker this class handles passes through
// untouched. Do not re-enable without new evidence of what's actually
// safe.
//
// Slime-name rosters -- opcode 0x4E, confirmed on five markers so far.
// Two are the entrant list shown during a Slime Race (each entrant's player
// name AND their slime's own player-chosen nickname); one is a plain
// listing of your OWN slimes' names outside of a race (stable/pen view);
// one looks like a post-race results/standings screen (repeats a name --
// see below); one looks like a single-slime detail view (exactly one
// name, the same shape as AllianceMemberDetailPacket vs.
// AllianceMemberListPacket, or TavernRecruitmentDetailPacket vs. -List).
// Not to be confused with CasinoPlayerListPacket, which shares opcode 0x4E
// but a different marker (0x7E96) and a completely different, explicitly
// length-prefixed record shape; also not to be confused with
// WeeklyRequestPacket, which shares the 0x6BB8 marker but a different
// opcode (0x46).
//
// NAMING: originally SlimeRacePlayerListPacket, renamed once the 0x69CA
// capture confirmed this same byte-level shape also carries a non-race
// "just your own slimes" listing with no player names at all -- same
// renaming situation CasinoPlayerListPacket went through (see that class's
// own NAMING note) once it turned out to not be Bingo-specific. The two
// later markers (0x20E7, 0x994B) stretch the name further still (results
// screen, single-slime detail) but the class keeps the name rather than
// renaming again each time a new marker turns up -- the byte-scan approach
// this class uses doesn't care what screen sent the packet, so there's no
// natural per-marker split point to name around.
//
// Five captures on file, all routed to this same class since they share
// the identical byte-level shape (same un-prefixed katakana name runs
// embedded in otherwise-opaque stats blocks):
//   0xA7AA: 4 entrants, 8 names (4 player/slime pairs) --
//     チオリ (player) / アイリン (slime)
//     ジャスミン (player) / アムリタ (slime)
//     アノーノ (player) / アンクル (slime)
//     ショウブ (player) / ドレイク (slime)
//   0x6BB8: same 4 pairs above PLUS a 9th, trailing name (カンカン) with no
//     paired name after it before the packet ends -- so the pairing isn't
//     load-bearing for anything this class does (see below), just useful
//     context for what the data represents.
//   0x69CA: no player names at all -- just 3 slime names back to back
//     (ドレイク, カンカン, バイト), confirming the byte-scan approach doesn't
//     depend on a player/slime pairing existing in the first place.
//   0x20E7: 4 names, but only 3 distinct -- ドレイク, カンカン, バイト, カンカン
//     again -- plus a substantial extra tail of binary after the last name
//     that none of the other captures have (likely race placement/timing
//     data for a results screen). The repeated カンカン is presumably that
//     slime appearing twice in the results structure (e.g. both in a
//     per-entrant list and a separate "your slime" highlight), not a
//     parsing error -- confirmed by re-checking the raw capture directly.
//   0x994B: exactly 1 name (ドレイク) -- looks like a single-slime detail
//     packet, the "record for one slime" counterpart to the roster/list
//     markers above.
//
// Layout is NOT fully understood for any of the five markers -- there's a
// header of varying size, then repeating stats blocks with a katakana name
// embedded somewhere inside, but the exact field semantics and record
// stride are unconfirmed and clearly differ across markers (0x69CA's and
// 0x994B's captures are much shorter overall than the two race-roster
// markers, and 0x20E7 has a large trailing block none of the others do).
//
// Rather than guess at the exact record layout per marker, this uses the
// same technique as HiredByListPacket (see that class's doc comment for the
// full reasoning): scan the raw payload directly for maximal runs of valid
// 3-byte UTF-8 sequences that decode into the hiragana/katakana range (plus
// the fullwidth tilde) -- i.e. find exactly where real character-name text
// starts and ends by looking at the bytes themselves, with no dependency on
// record boundaries, stride, or what precedes/follows a name. This finds
// every name cleanly in all three captures on file, with no false splits
// or merges, and needs no per-marker branching at all.
//
// CRITICALLY: none of the names across any of the five captures are
// preceded by a length prefix (checked the 4 bytes immediately before each
// name in every capture -- all zero except a couple of clearly-unrelated
// non-zero binary values, never a plausible byte count). That means --
// unlike CasinoPlayerListPacket/MonsterFarmListPacket, which both announce
// their name's length so a translation is free to grow or shrink -- these
// names most likely sit in fixed-width buffers read by position/stride
// rather than by an explicit length. Given this whole session's repeated
// lesson that letting a translated name change a packet's length (or shift
// anything positioned after it) crashes the DQX client
// (TeamJoinMessagePacket, HiredByListPacket, FriendRequestAcceptedPacket,
// HiredMemberExpirationPacket), every translated name here is written back
// into a slot pinned to exactly its ORIGINAL byte width -- truncated if the
// translation is longer, zero-padded if shorter -- so the packet's total
// length, and every byte position after each name, never changes regardless
// of what the true underlying struct layout turns out to be for any given
// marker.
//
// Per the user: both a player's own name and a slime's own nickname are
// player-chosen freeform text, so both are resolved identically --
// 'local_player_names' m00 dict first, romaji fallback on miss -- the same
// as every other player-chosen name in this codebase. There's no dedicated
// pet/slime-nickname dictionary, and a dict miss just falls through to the
// romanizer the same way any other unrecognized player name would.
//
// Per the user, this packet does NOT use EntityPacket's \x04 nameplate-icon
// prefix trick -- that's specific to EntityPacket's Player/Party/Fellow/
// PartyNpc kinds, not a general player-name-translation convention, and
// this class deliberately does not add it.
//
// Samples: docs/packets/references/slime_race_roster (0xA7AA, 8 names),
//          docs/packets/references/slime_race_roster_2 (0x6BB8, 9 names --
//          confirms the byte-scan approach holds even when the name count
//          isn't an even "player/slime pairs" total),
//          docs/packets/references/slime_own_name_list (0x69CA, 3 names --
//          confirms the same approach holds with no player names present
//          at all),
//          docs/packets/references/slime_race_results (0x20E7, 4 names,
//          3 distinct -- a repeated name plus a large unexplored trailing
//          block),
//          docs/packets/references/slime_detail (0x994B, 1 name -- the
//          single-slime-detail shape)
public sealed class SlimeRaceNameListPacket : IPacket
{
    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public SlimeRaceNameListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        // DISABLED -- see the class doc comment's "TRANSLATION CURRENTLY
        // DISABLED" note. A live capture of this exact fixed-width-slot
        // translation (applied to 0x69CA) crashed the DQX client, and
        // re-simulating the logic below against that capture reproduced
        // the crashing bytes exactly -- proving the bug isn't in HOW this
        // method would fill the slot (length/position are provably
        // correct), only in doing it at all for this packet family.
        // ModifiedData is deliberately left unset (null) so every marker
        // this class handles keeps passing through untouched until the
        // real cause is found. The scanning/translation helpers below
        // (JapaneseRunLength, IsJapaneseCodepoint, TryTranslate) are kept
        // as dormant, unused code rather than deleted, since whatever fix
        // this needs will likely still start from "find the katakana
        // runs" -- it just can't be this method's old unconditional
        // rewrite. Do not re-enable by just uncommenting the block below
        // without new evidence of what's actually safe here.
        //
        // var dict = _deps.M00Dict("local_player_names");
        // var changed = false;
        // var writer = new PacketWriter();
        //
        // var i = 0;
        // while (i < _raw.Length)
        // {
        //     var runLen = JapaneseRunLength(_raw, i);
        //     if (runLen == 0)
        //     {
        //         writer.WriteU8(_raw[i]);
        //         i++;
        //         continue;
        //     }
        //
        //     var text = Encoding.UTF8.GetString(_raw, i, runLen);
        //     if (TryTranslate(text, dict, out var newBytes))
        //     {
        //         changed = true;
        //         // Fixed-width slot: this run's ORIGINAL byte length.
        //         if (newBytes!.Length > runLen) newBytes = newBytes[..runLen];
        //         writer.WriteBytes(newBytes);
        //         writer.WriteBytes(new byte[runLen - newBytes.Length]); // zero-pad to original width
        //     }
        //     else
        //     {
        //         writer.WriteBytes(_raw.AsSpan(i, runLen).ToArray());
        //     }
        //
        //     i += runLen;
        // }
        //
        // if (!changed) return;
        // ModifiedData = writer.Build();
    }

    // Finds the length, in bytes, of the maximal run starting at `start`
    // made up entirely of valid 3-byte UTF-8 sequences that decode into the
    // hiragana/katakana range (plus the fullwidth tilde). Returns 0 if
    // `start` isn't the beginning of such a run. Operating on raw bytes
    // (rather than null-delimited chunks first) means this can't be fooled
    // by a name that isn't preceded by a 0x00 separator -- see HiredByList-
    // Packet's doc comment for the PartyInvitationPacket bug this avoids.
    //
    // Currently unused -- dormant alongside Build()'s disabled translation
    // block above (see that method's comment). Kept for whatever
    // investigation/fix comes next, not dead code to be deleted.
    private static int JapaneseRunLength(byte[] data, int start)
    {
        var i = start;
        while (i + 3 <= data.Length)
        {
            var b0 = data[i];
            var b1 = data[i + 1];
            var b2 = data[i + 2];
            if ((b0 & 0xF0) != 0xE0) break;                     // not a 3-byte utf-8 lead byte
            if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) break; // invalid continuation bytes
            var codepoint = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
            if (!IsJapaneseCodepoint(codepoint)) break;
            i += 3;
        }
        return i - start;
    }

    private static bool IsJapaneseCodepoint(int codepoint) =>
        (codepoint >= 0x3040 && codepoint <= 0x30FF) || // hiragana + katakana (includes ー U+30FC, ・ U+30FB)
        codepoint == 0xFF5E;                            // ～ fullwidth tilde -- character names can't contain kanji

    // `text` is already confirmed to be a clean run of Japanese characters
    // (see JapaneseRunLength) -- this only decides whether we have a
    // translation for it.
    private bool TryTranslate(string text, Dictionary<string, string> dict, out byte[]? newBytes)
    {
        newBytes = null;
        if (!Translator.IsTextJapanese(text)) return false;

        var resolved = dict.TryGetValue(text, out var known) && !string.IsNullOrEmpty(known)
            ? known
            : _deps.Romanizer.ToRomaji(text);

        if (string.IsNullOrEmpty(resolved) || resolved == text) return false;

        newBytes = Encoding.UTF8.GetBytes(resolved);
        return true;
    }
}
