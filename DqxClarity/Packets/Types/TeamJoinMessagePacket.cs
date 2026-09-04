using System.Text;

namespace DqxClarity.Packets.Types;

// The actual "<player> joined the Team!" toast/chat-log message. Same
// opcode family (0x0d) as TeamJoinNotificationPacket (marker 0x9804), but a
// different marker (0x11c1) and — per the user, who reported the existing
// packet "doesn't do anything even after modifying it" — this is the one
// that's actually responsible for the visible notification. Left
// TeamJoinNotificationPacket in place rather than replacing it: whatever
// 0x9804 actually is, it's still a distinct, real packet, just not this one.
//
// UPDATE: if you log in after several people joined the Team while you were
// offline, the game bundles ALL of those pending join notifications into a
// single packet — one join-record per player, back to back. A capture with
// 2 pending joins confirmed this: the previous single-name implementation
// (fixed 28-byte header, one name cstring, then an opaque 107-byte
// "remainder") only ever found and translated the FIRST name. Scanning that
// capture for every valid Japanese run turned up THREE, not two: セラ
// (where the old code already looked, right after the header), あああああ
// (a second player's name, deep inside what used to be treated as opaque
// passthrough remainder), and エヴィ in between the two — likely a piece of
// per-record data (equipment/fashion name?) rather than a player name, role
// unconfirmed. There's no reliable way to know the per-record stride/count
// up front (same situation as AllianceMemberListPacket's alliance roster),
// so this was rewritten to use that packet's approach instead of assuming a
// single fixed record shape.
//
// Approach: scan the raw payload directly for maximal runs of valid 3-byte
// UTF-8 sequences that decode into the hiragana/katakana/common-kanji
// ranges (JapaneseRunLength), translate every run found — however many
// there are, whatever they turn out to be — and leave everything else
// (header, per-record binary, whatever's between/after the names)
// completely untouched. This needs no knowledge of record boundaries or how
// many pending joins are bundled in, but it does mean any Japanese text
// riding along in a record (like エヴィ above) now gets swept up and
// translated too, not just the player name -- same tradeoff already made
// for AllianceMemberListPacket/PartyInvitationPacket/HiredByListPacket.
//
// CONFIRMED CRASH, now fixed (this constraint still applies with the new
// approach): an earlier version of this class let a name field grow/shrink
// freely (relying on GamePacket's outer wire-frame resize, same as
// NpcDialoguePacket/MailMessagePacket/etc.). That assumption holds for
// actual dialogue/text-box packets, but not here -- a capture with
// "やんもら" (12 utf-8 bytes) translated to "Yanmora" (7 bytes) crashed the
// game. Byte-level comparison of the original vs. modified wire capture
// showed the outer size byte *was* correctly recalculated (159 -> 154) and
// every field after the name shifted left by exactly 5 bytes, content
// unchanged -- so the bug isn't in our reconstruction, it's that the
// client evidently reads these messages' fields at fixed offsets from the
// packet start rather than scanning for a name's null terminator. Shrinking
// any name shifts every later field out from under a fixed-offset reader.
// Fix (same as PartyInvitationPacket/AllianceMemberListPacket/etc.): every
// translated name is truncated/zero-padded to fit exactly where the
// original run was, so no name translation can ever change the packet's
// total length or shift anything after it.
//
// BUG FOUND + FIXED (via AllianceMemberDetailPacket's あ～にゃ capture):
// JapaneseRunLength originally only recognized the hiragana/katakana/kanji
// codepoint ranges, so a name containing the fullwidth tilde (～, U+FF5E --
// confirmed the only punctuation besides ー/・, both already in the
// hiragana/katakana range, that can appear in a player name) would get
// split into multiple separate runs. Each run was then independently
// truncated/zero-padded to its OWN width -- if an earlier run's
// translation was shorter than the original, the zero-padding landed a
// NUL byte in the MIDDLE of the name, which the game's cstring reader
// reads as an early terminator, silently dropping everything after it.
// Fixed by adding U+FF5E to IsJapaneseCodepoint so such a name scans as
// ONE run and is translated/padded as a single unit. IsJapaneseCodepoint
// also does NOT scan for kanji -- confirmed by the user, character names
// can only ever contain hiragana and katakana.
//
// Names are resolved the same way TeamJoinNotificationPacket/EntityPacket
// resolve a Player entity's name: 'local_player_names' m00 dict first,
// romaji fallback on miss.
//
// Sample: docs/packets/references/team_join_message,
//         docs/packets/references/team_join_message_crash_original +
//         _crash_modified (the "やんもら"/"Yanmora" original+modified pair
//         that crashed, saved as proof of the bug the fixed-width-slot fix
//         addresses),
//         docs/packets/references/team_join_message_multi (the 2-name,
//         "logged in after multiple people joined" capture that exposed
//         the single-name limitation: セラ + あああああ)
public sealed class TeamJoinMessagePacket : IPacket
{
    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public TeamJoinMessagePacket(byte[] payloadData, PacketDependencies deps)
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
                // the class doc comment -- letting a translated name change
                // a record's length crashed the game (the "やんもら"/
                // "Yanmora" capture), so the translation is
                // truncated/zero-padded to fit exactly where the original
                // run was.
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
