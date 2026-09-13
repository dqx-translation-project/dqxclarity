using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The Tavern's "looking for party" board -- up to 5 pages of up to 20
// recruitment listings, 20 total, each with a player name and (optionally)
// a free-text recruitment message. The server always sends all 20 in one
// packet regardless of which page the client is showing.
//
// HEADER SIZE BUG (found and fixed): this file previously had
// HeaderBytes = 0x22 (34), which is 6 bytes too many. Every record's real
// index marker sits exactly 6 bytes before where that put it -- confirmed
// by scanning a live capture for the u32(1)/u32(index)/u32(0) marker
// pattern directly: all 20 markers landed at a constant -6 offset from the
// old assumed recordStart. Using HeaderBytes = 0x1C (28) instead makes
// every record boundary line up exactly, with (packet length - 0x1C)
// dividing evenly by the 0xE7 stride for the first time (it never had
// before, with 0x22). With the old, too-large header, EVERY record's
// name/index-marker window was quietly shifted 6 bytes into what should
// have been the tail end of the previous field -- for most records this
// still decoded as some plausible-looking (but wrong) run of kana, which
// is why it went unnoticed; it only became obviously visible for names
// where the shift happened to land exactly on a 2-character (6-byte)
// boundary, dropping precisely "the first two characters" and translating
// only the remainder -- e.g. "ぷそヤスーー" reading as "ヤスーー", with the
// dropped "ぷそ" bytes then getting copied through untouched as if they
// were still part of the (mis-sized) previous record's trailing bytes.
// The same off-by-6 also undercounted how many full records fit in the
// packet ((length - 34) / 231 truncated to 19 instead of the true 20),
// silently dropping the 20th listing into the untranslated leftover-bytes
// passthrough at the bottom of Build() every time.
//
// Fixed layout, reverse-engineered from a 20-listing capture (4654 bytes
// total):
//   header    0x1C (28) bytes -- passthrough
//   record[0..20)  0xE7 (231) bytes each, back to back, no gap, filling the
//                  rest of the packet exactly (28 + 20*231 = 4648, matching
//                  a live capture's _raw length exactly)
//
// Each 231-byte record:
//   index_marker  12 bytes -- u32(1), u32(record index, 1-based), u32(0).
//                 Passthrough; used only to locate the record boundaries
//                 during analysis.
//   name          cstring (utf-8, null-terminated) starting at record
//                 offset 0x0C -- confirmed at a FIXED offset in all 20
//                 records of the sample capture (one record's name started
//                 with a decorative "～", which is why a raw byte-run scan
//                 alone would've clipped it -- reading the actual
//                 null-terminated cstring at this known offset gets the
//                 whole thing, tildes included).
//   ...           stats/binary, unexamined
//   message       cstring, starting at record offset 0x6B in the listings
//                 that have one (several listings in the sample had none --
//                 an empty/all-zero cstring at that offset).
//   ...           remaining stats/binary, unexamined
//
// Deliberately only the name field is touched. The message field is real
// free-form player text (not a "name", not curated dialogue), and this
// packet belongs to the fixed-offset "roster" family (see
// PartyInvitationPacket/AllianceMemberListPacket/TeamJoinMessagePacket's
// doc comments for the fixed-offset-read crash class those packets hit) --
// letting a message's length change would shift every record after it. A
// dedicated free-text fix for the message field (if ever wanted) would need
// its own decision about how to handle that risk; out of scope here since
// only names were asked for.
//
// Names are resolved the same way every other player name in this codebase
// is: m00 'local_player_names' dict first, romaji fallback when the name
// isn't in the dict.
//
// Fixed-width slot (same fix as the rest of this packet family): a
// translated name is truncated/zero-padded to fit exactly where the
// original name's bytes were, so translating a name can never change a
// record's length or shift anything after it.
//
// Sample: docs/packets/references/tavern_recruitment_list (20/20 listings)
public sealed class TavernRecruitmentListPacket : IPacket
{
    private const int HeaderBytes = 0x1C;
    private const int RecordStride = 0xE7;
    private const int RecordCount = 20;
    private const int NameFieldOffset = 0x0C;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public TavernRecruitmentListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < HeaderBytes) return;

        var dict = _deps.M00Dict("local_player_names");
        var changed = false;
        var writer = new PacketWriter();

        writer.WriteBytes(_raw.AsSpan(0, HeaderBytes).ToArray());

        var recordCount = Math.Min(RecordCount, (_raw.Length - HeaderBytes) / RecordStride);
        for (var r = 0; r < recordCount; r++)
        {
            var recordStart = HeaderBytes + r * RecordStride;
            var recordEnd = recordStart + RecordStride;
            var nameStart = recordStart + NameFieldOffset;

            // index marker -- passthrough
            writer.WriteBytes(_raw.AsSpan(recordStart, NameFieldOffset).ToArray());

            // name cstring: find its null terminator within the record
            var nameEnd = nameStart;
            while (nameEnd < recordEnd && _raw[nameEnd] != 0) nameEnd++;
            var nameLen = nameEnd - nameStart;
            var name = nameLen > 0 ? Encoding.UTF8.GetString(_raw, nameStart, nameLen) : "";

            var newName = ResolveName(name, dict);
            if (nameLen > 0 && newName != name)
            {
                changed = true;
                // Fixed-width slot: original name's byte length. See the
                // class doc comment -- this packet's records are laid out
                // at fixed offsets, same fixed-offset-read risk as the rest
                // of this packet family, so the translation is
                // truncated/zero-padded to fit exactly where the original
                // name was.
                var newBytes = Encoding.UTF8.GetBytes(newName);
                if (newBytes.Length > nameLen) newBytes = newBytes[..nameLen];
                writer.WriteBytes(newBytes);
                writer.WriteBytes(new byte[nameLen - newBytes.Length]); // zero-pad to original width
            }
            else
            {
                writer.WriteBytes(_raw.AsSpan(nameStart, nameLen).ToArray());
            }

            // null terminator through the rest of the record (stats, message
            // field, trailing padding) -- passthrough, untouched.
            writer.WriteBytes(_raw.AsSpan(nameEnd, recordEnd - nameEnd).ToArray());
        }

        // Any bytes beyond the last full record (shouldn't happen given the
        // sample's exact header + 20*stride fit, but don't silently drop
        // anything if a future capture is shaped differently).
        var consumed = HeaderBytes + recordCount * RecordStride;
        if (consumed < _raw.Length)
            writer.WriteBytes(_raw.AsSpan(consumed, _raw.Length - consumed).ToArray());

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
