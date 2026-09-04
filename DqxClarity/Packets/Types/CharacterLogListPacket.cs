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
// Sample: docs/packets/references/character_log_list
public sealed class CharacterLogListPacket : IPacket
{
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

        if (!changed) return;
        ModifiedData = writer.Build();
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
