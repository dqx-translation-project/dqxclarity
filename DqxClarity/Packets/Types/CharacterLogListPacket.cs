using System.Buffers.Binary;
using System.Text;

namespace DqxClarity.Packets.Types;

// The "character log" -- the player's own character plus their sibling,
// shown side by side, up to 5 character-pair slots (opcode 0x87, marker
// 0xf7f5). A u32 count field at Data offset 0x08 gives how many of the 5
// slots are populated (3 in the sample capture); each populated slot holds
// a player name and, immediately after it in the same record, that
// character's sibling's name.
//
// Confirmed fixed-offset "roster" family, the same way PartyInvitationPacket/
// AllianceMemberListPacket/AllianceMemberDetailPacket/TeamJoinMessagePacket
// were: the sample capture's 6 Japanese runs (3 player names + 3 sibling
// names) sit at offsets whose deltas alternate a constant 75 / 105 bytes
// (0x4B / 0x69) despite the runs themselves having different byte lengths
// (player names 12/15/18 bytes; sibling names 9/12/18 bytes) -- conclusive
// proof of a fixed-width-slot record layout (each player+sibling pair
// record is a constant 180 bytes wide, with the sibling name starting 75
// bytes after the player name within it), not something that just happens
// to look that way because the sample names were coincidentally similar.
//
// Approach + fix: identical byte scan to AllianceMemberListPacket/
// AllianceMemberDetailPacket -- scan the raw payload directly for maximal
// runs of valid 3-byte UTF-8 sequences that decode into the hiragana/
// katakana/common-kanji ranges (JapaneseRunLength), translate the run
// found, truncated/zero-padded to fit exactly where the original run was
// so no record's length -- and therefore no other slot's position -- can
// ever shift. This needs no knowledge of the 180-byte stride, the 75-byte
// player-to-sibling offset, or the 0x08 count field at all, so it holds
// regardless of how many of the 5 slots are populated.
//
// Same fullwidth-tilde fix applied to AllianceMemberListPacket/
// TeamJoinMessagePacket after a bug was found in AllianceMemberDetailPacket:
// JapaneseRunLength recognizes U+FF5E (～) alongside the hiragana/katakana
// range, so a name containing it scans as ONE run instead of being split
// into pieces that would each get independently zero-padded (which can
// plant a stray NUL mid-name and truncate everything after it -- see
// AllianceMemberDetailPacket's doc comment for the full failure mode). ー
// (U+30FC) and ・ (U+30FB), the only other punctuation confirmed to appear
// in player names, are already inside the hiragana/katakana range. No
// kanji range is scanned for -- confirmed by the user, character names can
// only ever contain hiragana and katakana.
//
// Both the player's own name and the sibling's name are resolved with the
// same "normal player name logic" every other player-chosen name in this
// codebase uses: m00 'local_player_names' dict first, romaji fallback on
// miss (see SiblingNamePacket, which resolves the same sibling name the
// same way for the in-scene case). No leading \x04 GM-face-prevention byte
// is applied here -- that trick has only ever been added to packets on
// explicit request (AllianceMemberListPacket, AllianceMemberDetailPacket);
// add it the same way (see TryTranslate in either of those) if this list
// turns out to need it too.
//
// Beyond the display translation above, each record also carries two more
// fixed-offset fields relative to its own player-name start (call that
// offset P, with record N's P = 36 + N*stride; stride 180 before 8.1, 225
// from 8.1 -- the offsets below are the pre-8.1 ones, see 8.1 UPDATE):
//   - a persistent u32 character id at P-24 (i.e. Data offset 12 + N*180) --
//     confirmed identical, byte for byte, to the id EntityPacket reports for
//     that same character's Player-kind entity, captured a full week apart.
//     See PlayerContext, which uses this correlation to figure out which
//     roster slot is the currently logged-in character without a login hook.
//   - a relationship byte at P+94 (Data offset 130 + N*180, equivalently 19
//     bytes after the sibling name's fixed 19-byte slot starts) -- confirmed
//     against four real captures spanning all four possible values: 1 =
//     older_brother, 2 = younger_brother, 3 = older_sister, 4 =
//     younger_sister. Exactly matches main branch's own
//     _determine_sibling_relationship encoding. See SiblingRelationship.
// UpdateRoster reads both fields (plus the ja names, read straight rather
// than through the translate-in-place byte scan above) and republishes them
// into PacketDependencies.PlayerRoster on every capture, independent of
// whether the display-translation pass below changes anything -- the roster
// needs to stay current even on a capture with nothing new to translate.
//
// 8.1 UPDATE: the record grew from 180 to 225 bytes, and the sibling name
// (and the relationship byte that follows it) moved from 75 to 139 bytes
// after the player name. Everything else is unchanged: the count is still at
// Data offset 8, record 0's player name is still at 36, the character id is
// still 24 bytes before its player name, and the sibling name slot is still
// 19 bytes with the relationship byte right after it. Confirmed from a
// 3-record capture (Shobu/Katta = younger_brother, Ellistan/Colette =
// older_sister, New York/Rochester = younger_sister): player names at Data
// 36 / 261 / 486, sibling names at 175 / 400 / 625, relationship bytes at
// 194 / 419 / 644 holding 2 / 3 / 4. The display translation below never
// noticed, because it scans for Japanese runs and needs no offsets -- but the
// roster read (UpdateRoster) uses the offsets above, so after 8.1 it read the
// sibling name and relationship from the wrong place and the player/sibling/
// sibling_relationship rows in the database came out empty.
//
// The layout is therefore no longer a constant: UpdateRoster tries each known
// layout (RosterLayouts, newest first) and uses the first one where every
// populated record checks out -- player and sibling names are readable text,
// the relationship byte is 1-4. If none fits, the packet is left untouched
// and reported (PacketLayoutException -> MismatchReporter) instead of
// quietly writing garbage into the database again. Add the new stride and
// sibling offset to RosterLayouts if a later patch moves things again.
//
// Sample: docs/packets/references/character_log_list (pre-8.1, 180-byte records),
//         character_log_list_2 (8.1, 225-byte records)
public sealed class CharacterLogListPacket : IPacket
{
    private const int CountOffset = 0x08;
    private const int MaxRecords = 5;
    private const int RecordIdOffset = 12;           // record 0's character-id u32
    private const int RecordPlayerNameOffset = 36;   // record 0's player-name cstring start
    private const int SiblingSlotBytes = 19;         // relationship byte = sibling name start + this
    private const int MaxNameBytes = 40;             // longest cstring read while probing a layout

    // Where things sit within the roster, per game version. SiblingFromPlayer
    // is the distance from a record's player-name start to its sibling-name
    // start; the relationship byte is SiblingSlotBytes after that. Newest
    // first, so a current packet is never mistaken for an older layout.
    private readonly record struct RosterLayout(string Name, int Stride, int SiblingFromPlayer);

    private static readonly RosterLayout[] RosterLayouts =
    {
        new("8.1",     225, 139),
        new("pre-8.1", 180, 75),
    };

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public CharacterLogListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        var dict = _deps.M00Dict("local_player_names");
        var changed = false;
        var writer = new PacketWriter();

        var i = 0;
        while (i < _raw.Length)
        {
            var runLen = JapaneseRunLength(_raw, i);
            if (runLen == 0)
            {
                writer.WriteU8(_raw[i]);
                i++;
                continue;
            }

            var text = Encoding.UTF8.GetString(_raw, i, runLen);
            if (TryTranslate(text, dict, out var newBytes))
            {
                changed = true;
                // Fixed-width slot: this run's ORIGINAL byte length. See
                // the class doc comment -- the confirmed constant 180-byte
                // record stride means a translation is truncated/
                // zero-padded to fit exactly where the original run was.
                if (newBytes!.Length > runLen) newBytes = newBytes[..runLen];
                writer.WriteBytes(newBytes);
                writer.WriteBytes(new byte[runLen - newBytes.Length]); // zero-pad to original width
            }
            else
            {
                writer.WriteBytes(_raw.AsSpan(i, runLen).ToArray());
            }

            i += runLen;
        }

        if (changed) ModifiedData = writer.Build();

        // After the translation pass, so it is the roster read that decides
        // whether this packet's layout is understood. Throws
        // PacketLayoutException (-> packet left as the game sent it, plus a
        // mismatch report) when it is not.
        UpdateRoster();
    }

    // Reads the id/name/relationship fields documented in the class comment
    // above for however many of the up to 5 slots are populated, and
    // publishes them to the shared roster. Independent of the display-
    // translation byte scan in Build() -- a record that needs no translation
    // still needs to be in the roster.
    //
    // Tries each known layout and keeps the first one that fits every
    // populated record; throws PacketLayoutException when none does.
    private void UpdateRoster()
    {
        if (_raw.Length < CountOffset + 4) return;
        var count = BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(CountOffset, 4));
        var slots = (int)Math.Min(count, MaxRecords);
        if (slots == 0) return;

        foreach (var layout in RosterLayouts)
        {
            if (!TryReadRoster(layout, slots, out var entries)) continue;
            _deps.PlayerRoster.Update(entries);
            _deps.PlayerContext.NotifyRosterUpdated(_deps);
            return;
        }

        throw new PacketLayoutException(
            $"Character log: {slots} record(s) do not fit any known layout " +
            $"(strides {string.Join("/", RosterLayouts.Select(l => l.Stride))})",
            RecordPlayerNameOffset);
    }

    // True when every populated record under `layout` holds a readable player
    // name, a readable sibling name and a relationship byte of 1-4. A record
    // that is cut off by the end of the packet ends the list (as before).
    private bool TryReadRoster(RosterLayout layout, int slots, out List<CharacterRosterEntry> entries)
    {
        entries = new List<CharacterRosterEntry>(slots);

        for (var i = 0; i < slots; i++)
        {
            var playerOffset = RecordPlayerNameOffset + i * layout.Stride;
            var siblingOffset = playerOffset + layout.SiblingFromPlayer;
            var relationshipOffset = siblingOffset + SiblingSlotBytes;
            if (relationshipOffset >= _raw.Length) break; // record not fully present in this capture

            var relationshipByte = _raw[relationshipOffset];
            if (relationshipByte < 1 || relationshipByte > 4) return false;

            if (!TryReadCStringAt(playerOffset, out var playerName) || playerName.Length == 0) return false;
            if (!TryReadCStringAt(siblingOffset, out var siblingName) || siblingName.Length == 0) return false;

            var idOffset = RecordIdOffset + i * layout.Stride;
            var id = BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(idOffset, 4));

            entries.Add(new CharacterRosterEntry(id, playerName, siblingName, relationshipByte));
        }

        return entries.Count > 0;
    }

    // Null-terminated text at `offset`. False when it isn't text, or has no
    // terminator within MaxNameBytes -- both mean "not where we think it is".
    private bool TryReadCStringAt(int offset, out string text)
    {
        text = "";
        if (offset < 0 || offset >= _raw.Length) return false;
        var span = _raw.AsSpan(offset);
        var nul = span.IndexOf((byte)0);
        if (nul < 0 || nul > MaxNameBytes) return false;
        return PacketText.TryDecode(span[..nul], out text);
    }

    // Finds the length, in bytes, of the maximal run starting at `start`
    // made up entirely of valid 3-byte UTF-8 sequences that decode into the
    // hiragana/katakana/common-kanji ranges. Returns 0 if `start` isn't the
    // beginning of such a run.
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
        (codepoint >= 0x3040 && codepoint <= 0x30FF) || // hiragana + katakana (includes ー U+30FC, ・ U+30FB) -- no kanji range: character names can never contain kanji
        codepoint == 0xFF5E;                            // ～ fullwidth tilde -- confirmed the only other punctuation mark that can appear in a player name

    // `text` is already confirmed to be a clean run of Japanese characters
    // (see JapaneseRunLength) -- this only decides whether we have a
    // translation for it.
    private bool TryTranslate(string text, Dictionary<string, string> dict, out byte[]? newBytes)
    {
        newBytes = null;

        var resolved = dict.TryGetValue(text, out var known) && !string.IsNullOrEmpty(known)
            ? known
            : _deps.Romanizer.ToRomaji(text);

        if (string.IsNullOrEmpty(resolved) || resolved == text) return false;

        newBytes = Encoding.UTF8.GetBytes(resolved);
        return true;
    }
}
