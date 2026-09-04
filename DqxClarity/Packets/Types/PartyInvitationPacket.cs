using System.Text;

namespace DqxClarity.Packets.Types;

// A party invitation, listing up to 4 prospective party members. The first
// capture had 2 populated ("バンダル" and "キュ"); a later single-member
// capture ("みるく") exposed a real bug in how names were being located --
// see below.
//
// This is a sibling of the other party/* packets (PartyListPacket,
// PartyList2-4Packet), all of which use a FIXED-WIDTH, zero-padded name
// slot with a fixed per-entry stride, and translate by truncating the
// romaji replacement to fit that slot. This packet looks the same at
// first glance -- member 1's name ("バンダル", 12 utf-8 bytes) is followed
// by a null terminator and then 7 more zero bytes before the next
// non-zero field, suggesting a 20-byte padded slot -- but member 2
// contradicts that theory: "キュ" (6 utf-8 bytes) is followed by its null
// terminator and then *immediately* by non-zero data (no padding at all).
// So this does NOT use a fixed-slot/truncate-from-a-known-stride approach.
//
// CONFIRMED CRASH on the sibling TeamJoinMessagePacket (0x0d/0x11c1) proved
// that letting a translated name change the packet's total length breaks
// this whole family of roster/notification packets -- DQX's client reads
// at least some fields at offsets fixed relative to the packet start, not
// by scanning for each name's null terminator. So every translated name
// here is written back into a slot of exactly its ORIGINAL byte width
// (truncated/zero-padded to fit), same fix as that packet.
//
// CONFIRMED BUG (blank name), now fixed: an earlier version of this class
// found "the name" by splitting the WHOLE payload on every raw 0x00 byte
// and treating each resulting chunk as a candidate name. That assumes each
// name is bounded by 0x00 on *both* sides, which turned out to be false --
// in the "みるく" single-member capture, the name's leading byte is
// immediately preceded by non-zero binary ("E9 03 B4 01 E9 03 D2 01", a
// tick-id field) with no null separator at all. The old null-scan lumped
// those 8 unrelated binary bytes into the same "segment" as the name, ran
// them through Encoding.UTF8.GetString (which doesn't throw on invalid
// bytes -- it substitutes U+FFFD and carries on), got a garbled
// binary+name string, and fed *that* to the dictionary/romanizer. Whatever
// came back got forced into the (wrong, binary-inclusive) slot width,
// stomping real packet data and leaving the name unreadable -- reported by
// a user as the name appearing blank in-game.
//
// Fixed by not using 0x00 as a boundary at all. Instead this scans the raw
// bytes directly for maximal runs of valid 3-byte UTF-8 sequences that
// decode into the hiragana/katakana/common-kanji ranges (JapaneseRunLength)
// -- i.e. it finds exactly where real Japanese text starts and ends by
// looking at the bytes themselves, regardless of what precedes or follows
// them. Only that exact run gets translated and slot-width-preserved; the
// binary bytes before it (and the 0x00 terminator plus everything after)
// are copied through completely untouched. This is stricter than the old
// "does it decode as Japanese at all" check and sidesteps the whole class
// of "name glued to unrelated preceding binary" bug -- it should also be
// immune to whatever the true per-slot record layout/stride actually is,
// same as the null-scan approach was trying (and failing) to achieve.
//
// Each member's name is bracketed by a repeated 4-byte id (member 1:
// "95 B5 AE 22"; member 2: "E2 58 17 08"; single-member "みるく" capture:
// "3A 0D 2C 01"), a reassuring sign the record structure is sane even
// though the exact stride isn't pinned down -- but nothing here depends on
// that id.
//
// Character names can only ever contain hiragana, katakana, and (confirmed
// by the user) the fullwidth tilde (～, U+FF5E) as punctuation -- ー
// (U+30FC) and ・ (U+30FB) are already inside the hiragana/katakana range.
// No kanji range is scanned for, and IsJapaneseCodepoint recognizes U+FF5E
// explicitly, so a name like "あ～にゃ" (see AllianceMemberDetailPacket's
// doc comment for the bug this avoids) scans as ONE run instead of being
// split into pieces that would each get independently zero-padded.
//
// Names are resolved the same way TeamJoinNotificationPacket/
// HiredByListPacket resolve an arbitrary player name: m00
// 'local_player_names' first, romaji fallback on miss -- these are
// player-chosen character names, not curated dialogue.
//
// Samples: docs/packets/references/party_invitation,
//          docs/packets/references/party_invitation_single_member (the
//          "みるく" capture that exposed the null-scan bug this fix
//          addresses; also contains a second name, "タルト", elsewhere in
//          the packet that is NOT the party member shown in the invite UI
//          -- translating it is harmless either way since it's handled
//          the same as any other name-shaped run in the payload) +
//          _modified (the buggy null-scan output the user actually saw --
//          byte diff against the original confirms the exact corruption
//          predicted above: "Miruku" landed 8 bytes early at the position
//          of the tick-id that used to precede "みるく", overwriting it,
//          while the real name slot the client reads from was left as
//          zero padding; same pattern, 4 bytes early, for "Taruto")
public sealed class PartyInvitationPacket : IPacket
{
    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public PartyInvitationPacket(byte[] payloadData, PacketDependencies deps)
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
                // change the packet's total length crashed the client on
                // the sibling TeamJoinMessagePacket, so the translation is
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
