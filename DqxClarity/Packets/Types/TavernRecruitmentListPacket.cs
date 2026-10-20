using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The Tavern's "looking for party" board -- up to 5 pages of up to 20
// recruitment listings, 20 total, each with a player name and (optionally)
// a free-text recruitment message. The server always sends all 20 in one
// packet regardless of which page the client is showing.
//
// 8.1 UPDATE: the record stride grew from 0xE7 (231) to 0xEB (235) bytes.
// Header (28) and the 20-record count are unchanged, so only the first
// listing lined up with the old stride and every later name was read from the
// wrong place. 28 + 20 * 235 = 4728, which is exactly the Data length of a
// post-8.1 capture (frame size 0x127B minus opcode + marker).
//
// The stride is no longer a constant: it is worked out from the packet as
// (Data length - header) / record count, so a future patch that only grows or
// shrinks the records keeps working. The record count comes from the u32 at
// header offset 0x18 (always 20 so far; the constant is the fallback). Every
// record is then checked against its index marker -- u32(1), u32(index),
// u32(0) -- and a packet whose records do not line up is left completely
// untouched and reported (PacketLayoutException -> MismatchReporter) instead
// of being rewritten at the wrong offsets.
//
// Note on the old reference sample (docs/packets/references/
// tavern_recruitment_list): it was stored with LF -> CRLF conversion applied
// (every 0x0A byte is preceded by a 0x0D), which makes its records look like
// 231/232 bytes and breaks one index marker. The real stride in the old
// layout was 231; do not use that file to verify a stride.
//
// Layout (post-8.1, reverse-engineered from a 20-listing capture):
//   header    0x1C (28) bytes -- passthrough. u32 at 0x18 = record count (20).
//   record[0..20)  stride bytes each, back to back, no gap, filling the rest
//                  of the packet exactly.
//
// Each record:
//   index_marker  12 bytes -- u32(1), u32(record index, 1-based), u32(0).
//                 Passthrough; used to verify the record boundaries.
//   name          cstring (utf-8, null-terminated) starting at record
//                 offset 0x0C. May start with a decorative "~", so the whole
//                 null-terminated string is read.
//   ...           stats/binary, unexamined
//   message       cstring, free-form player text (not touched -- see below)
//   ...           remaining stats/binary, unexamined
//
// Deliberately only the name field is touched. The message field is real
// free-form player text, and this packet belongs to the fixed-offset
// "roster" family (see PartyInvitationPacket/AllianceMemberListPacket/
// TeamJoinMessagePacket's doc comments for the fixed-offset-read crash class
// those packets hit) -- letting a message's length change would shift every
// record after it.
//
// Names are resolved the same way every other player name in this codebase
// is: m00 'local_player_names' dict first, romaji fallback when the name
// isn't in the dict.
//
// Fixed-width slot: a translated name is truncated/zero-padded to fit exactly
// where the original name's bytes were, so translating a name can never
// change a record's length or shift anything after it.
//
// Safeguards: a name slot that does not hold text is skipped; if listings are
// present but none has a readable name the packet is reported as a layout
// mismatch.
//
// Sample: docs/packets/references/tavern_recruitment_list (20/20 listings)
public sealed class TavernRecruitmentListPacket : IPacket
{
    private const int HeaderBytes = 0x1C;
    private const int CountOffset = 0x18;
    private const int DefaultRecordCount = 20;
    private const int MaxRecordCount = 64;
    private const int MinRecordStride = 0x40;
    private const int MaxRecordStride = 0x800;
    private const int MarkerBytes = 12;
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

        var (recordCount, stride) = ResolveShape();

        var dict = _deps.M00Dict("local_player_names");
        var result = (byte[])_raw.Clone();
        var changed = false;
        var populated = 0;
        var readable = 0;

        for (var r = 0; r < recordCount; r++)
        {
            var recordStart = HeaderBytes + r * stride;
            var recordEnd = recordStart + stride;

            if (!MarkerMatches(recordStart, r + 1))
            {
                // An unused slot is all zeros; anything else means the records
                // are not where we think they are.
                if (IsZero(recordStart, MarkerBytes)) continue;
                throw new PacketLayoutException(
                    $"Tavern listing {r + 1} does not start with its index marker (stride {stride})",
                    recordStart);
            }

            populated++;

            var nameStart = recordStart + NameFieldOffset;
            var nameEnd = nameStart;
            while (nameEnd < recordEnd && _raw[nameEnd] != 0) nameEnd++;
            var nameLen = nameEnd - nameStart;
            if (nameLen == 0) { readable++; continue; }

            if (!PacketText.TryDecode(_raw.AsSpan(nameStart, nameLen), out var name)) continue;
            readable++;

            var newName = ResolveName(name, dict);
            if (newName == name) continue;

            // Fixed-width slot: original name's byte length, cut on a
            // character boundary, zero-padded to the original width.
            var newBytes = FitToWidth(newName, nameLen);
            if (newBytes.Length == 0) continue;

            Array.Clear(result, nameStart, nameLen);
            Buffer.BlockCopy(newBytes, 0, result, nameStart, newBytes.Length);
            changed = true;
        }

        if (populated > 0 && readable == 0)
            throw new PacketLayoutException(
                "Tavern listings found but none of the name slots hold text", HeaderBytes + NameFieldOffset);

        if (changed) ModifiedData = result;
    }

    // Record count and stride from the packet itself. The count in the header
    // is trusted only when it divides the remaining bytes exactly; otherwise
    // the usual 20 is tried. Anything else is a layout we do not know.
    private (int count, int stride) ResolveShape()
    {
        var body = _raw.Length - HeaderBytes;

        if (_raw.Length >= CountOffset + 4)
        {
            var hinted = BitConverter.ToInt32(_raw, CountOffset);
            if (hinted >= 1 && hinted <= MaxRecordCount && body % hinted == 0 && StrideOk(body / hinted))
                return (hinted, body / hinted);
        }

        if (body % DefaultRecordCount == 0 && StrideOk(body / DefaultRecordCount))
            return (DefaultRecordCount, body / DefaultRecordCount);

        throw new PacketLayoutException(
            $"Tavern list body of {body} bytes does not divide into whole records (header {HeaderBytes})",
            HeaderBytes);
    }

    private static bool StrideOk(int stride) => stride >= MinRecordStride && stride <= MaxRecordStride;

    private bool MarkerMatches(int offset, int index)
    {
        if (offset + MarkerBytes > _raw.Length) return false;
        return BitConverter.ToUInt32(_raw, offset) == 1
            && BitConverter.ToUInt32(_raw, offset + 4) == (uint)index
            && BitConverter.ToUInt32(_raw, offset + 8) == 0;
    }

    private bool IsZero(int offset, int count)
    {
        for (var i = 0; i < count && offset + i < _raw.Length; i++)
            if (_raw[offset + i] != 0) return false;
        return true;
    }

    private static byte[] FitToWidth(string text, int width)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        if (bytes.Length <= width) return bytes;

        // Back up to a character boundary so a multi-byte character is never cut in half.
        var len = width;
        while (len > 0 && (bytes[len] & 0xC0) == 0x80) len--;
        return bytes[..len];
    }

    private string ResolveName(string japanese, Dictionary<string, string> dict)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        if (dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known)) return known;
        return _deps.Romanizer.ToRomaji(japanese);
    }
}
