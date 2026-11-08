using System.Text;

namespace DqxClarity.Packets.Types;

// Login notification listing players who hired your character as support
// while you were offline. Holds up to 5 slots; the one capture available
// had 2 populated ("わりふと" and "ねこずき").
//
// CONFIRMED CRASH on the sibling TeamJoinMessagePacket (0x0d/0x11c1) proved
// that letting a translated name change the packet's total length breaks
// this whole family of roster/notification packets -- DQX's client reads
// at least some fields at offsets fixed relative to the packet start, not
// by scanning for each name's null terminator. So every translated name
// here is written back into a slot of exactly its ORIGINAL byte width
// (truncated/zero-padded to fit), same fix as that packet.
//
// CONFIRMED BUG on the sibling PartyInvitationPacket (0x03/0x66be), fixed
// here proactively: that class used to find "the name" by splitting the
// whole payload on every raw 0x00 byte and treating each chunk as a
// candidate name, assuming a name is always bounded by 0x00 on both sides.
// A real "みるく" capture proved that's false -- that name's leading byte
// was immediately preceded by non-zero binary (a tick-id field) with no
// null separator, so the null-scan lumped unrelated binary bytes into the
// same "segment", garbled it through Encoding.UTF8.GetString (which
// doesn't throw on invalid bytes, it substitutes and carries on), and fed
// the garbage to the dictionary/romanizer -- corrupting real packet data
// and leaving the name blank in-game. This class used the identical
// null-scan pattern, so it had the same latent bug even though the one
// capture on file happened to have a clean 0x00 immediately before each
// name.
//
// Fixed by not using 0x00 as a boundary at all. Instead this scans the raw
// bytes directly for maximal runs of valid 3-byte UTF-8 sequences that
// decode into the hiragana/katakana/common-kanji ranges
// (JapaneseRunLength) -- i.e. it finds exactly where real Japanese text
// starts and ends by looking at the bytes themselves, regardless of what
// precedes or follows them. Only that exact run gets translated and
// slot-width-preserved; everything else -- binary stat fields, empty
// slots, the 0x00 terminators -- is copied through completely untouched.
// This also sidesteps needing to know the exact per-slot record layout or
// stride, so it should hold regardless of how many of the 5 slots are
// populated.
//
// Character names can only ever contain hiragana, katakana, and (confirmed
// by the user) the fullwidth tilde (～, U+FF5E) as punctuation -- ー
// (U+30FC) and ・ (U+30FB) are already inside the hiragana/katakana range.
// No kanji range is scanned for, and IsJapaneseCodepoint recognizes U+FF5E
// explicitly, so a name like "あ～にゃ" (see AllianceMemberDetailPacket's
// doc comment for the bug this avoids) scans as ONE run instead of being
// split into pieces that would each get independently zero-padded.
//
// Names are resolved the same way TeamJoinNotificationPacket resolves an
// arbitrary player name: m00 'local_player_names' first, romaji fallback on
// miss -- these are player-chosen character names, not curated dialogue, so
// there's no fixed dictionary translation for most of them.
//
// Sample: docs/packets/references/hired_by_list
public sealed class HiredByListPacket : IPacket
{
    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public HiredByListPacket(byte[] payloadData, PacketDependencies deps)
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
