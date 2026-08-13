using System.Text;

namespace DqxClarity.Packets.Types;

// Roster of the "party alliance" -- a second party grouped alongside the
// player's own for content that supports it -- listing each member's name.
//
// Two real captures of the SAME alliance came in at very different total
// sizes (3098 vs. 2334 bytes) and the user was worried this meant the
// packet was broken or being misread. It isn't: a u32 member-count field
// at Data offset 0x20 reads 4 in the larger capture and 3 in the smaller
// one, and the smaller capture is otherwise an exact prefix of the larger
// one (same header, same first 3 members byte-for-byte structurally, same
// per-member record shape) -- it's simply missing the 4th member's entire
// record ("さるパーマ") because that member had left the alliance in the
// ~2 minutes between the two captures. The packet's total length is just
// proportional to how many alliance members currently exist; nothing here
// needs to read or trust that count to work correctly (see below).
//
// Each member's record also contains live stats (HP/MP/position/etc.)
// alongside the name, which explains the handful of other byte
// differences between the two captures scattered through each shared
// member's record -- ordinary gameplay-state churn, not part of the
// packet's mutable/checked structure and definitely not something to
// touch.
//
// Given the established risk with this whole packet family (see
// PartyInvitationPacket's doc comment for the "みるく" bug: a per-member
// record's exact layout/stride is not reliably knowable from a couple of
// captures, and null-terminator-based segmentation can accidentally lump
// a name together with adjacent binary fields when there's no 0x00
// separator immediately before it), this uses the same fix: scan the raw
// payload directly for maximal runs of valid 3-byte UTF-8 sequences that
// decode into the hiragana/katakana/common-kanji ranges
// (JapaneseRunLength), translate only the exact matched run, and leave
// every other byte -- header, member count, per-record stats, all of it
// -- completely untouched. This needs no knowledge of record boundaries,
// per-member stride, or the member count field at all, so it holds
// regardless of how many of the (apparently up to 4) alliance slots are
// populated.
//
// Same fixed-width-slot handling as every other packet in this family:
// a translated name is truncated/zero-padded to fit exactly where the
// original run was, so no name translation can ever change the packet's
// total length or shift anything after it -- only the alliance member
// count itself (which this never touches) changes the packet's size.
//
// Names are resolved the same way TeamJoinNotificationPacket resolves an
// arbitrary player name: m00 'local_player_names' first, romaji fallback
// on miss -- these are player-chosen character names, not curated
// dialogue.
//
// The resolved name is written with a leading \x04 byte (see TryTranslate)
// -- same trick EntityPacket uses for Player/Party nameplates -- to stop
// the game from rendering a GM-face icon next to the translated name.
//
// Samples: docs/packets/references/alliance_member_list_4 (4 members:
//          マリニア, ぱぶろ, だりあ, さるパーマ),
//          docs/packets/references/alliance_member_list_3 (same alliance,
//          ~2 minutes later, さるパーマ having left: マリニア, ぱぶろ,
//          だりあ)
public sealed class AllianceMemberListPacket : IPacket
{
    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public AllianceMemberListPacket(byte[] payloadData, PacketDependencies deps)
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
                // the class doc comment -- letting a translated name
                // change a record's length corrupted an unrelated field
                // and blanked the name on the sibling PartyInvitationPacket,
                // so the translation is truncated/zero-padded to fit
                // exactly where the original run was.
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
    // beginning of such a run. Operating on raw bytes (rather than
    // null-delimited chunks first) means this can't be fooled by a name
    // that isn't preceded by a 0x00 separator -- it only ever matches real,
    // well-formed Japanese text, wherever it starts.
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
        (codepoint >= 0x3040 && codepoint <= 0x30FF) || // hiragana + katakana
        (codepoint >= 0x4E00 && codepoint <= 0x9FFF);   // common kanji

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

        // \x04 prefix keeps the game from showing the GM-face icon next to the
        // translated name -- same trick EntityPacket uses for Player/Party
        // nameplates. It eats one byte of the fixed-width slot below, which in
        // practice only matters for the shortest 1-kana original names.
        newBytes = Encoding.UTF8.GetBytes("\x04" + resolved);
        return true;
    }
}
