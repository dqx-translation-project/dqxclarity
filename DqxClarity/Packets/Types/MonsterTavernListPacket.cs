using System.Buffers.Binary;
using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The Monster Tavern's deposit list -- monsters currently stored there, each
// with a player-assigned nickname. Up to 32 entries; the sample capture has
// 17 (a u32 count field at Data offset 0x0E reads 17, matching exactly --
// the "should have 16" estimate going in was off by one, same kind of
// off-by-one the AllianceMemberList investigation turned up).
//
// Unlike every other roster-style packet in this codebase
// (PartyInvitationPacket/AllianceMemberListPacket/TeamJoinMessagePacket/
// TavernRecruitmentListPacket), each entry here is NOT a fixed-size record.
// Every one of the 17 names in the sample is immediately preceded by its own
// u32 byte-length (name's utf-8 length including the null terminator) --
// confirmed against all 17: the u32 four bytes before each name's first byte
// exactly equals that name's utf-8 byte count + 1, every time. That's the
// same "length-prefixed cstring" shape EntityPacket already uses for
// Player/Party names, which are already proven safe to grow or shrink
// freely -- the client reads the length and advances by exactly that many
// bytes, rather than assuming a fixed offset for whatever comes next. This
// packet is architecturally the odd one out among the roster family
// precisely because it carries that explicit per-name length; none of the
// packets that turned out to need the fixed-width-slot fix had one.
//
// CAVEAT: that's an inference from the presence of the length prefix, not
// something crash-tested against a live capture the way the fixed-width-slot
// fix was proven necessary for TeamJoinMessagePacket. If a translated name
// here ever crashes or corrupts the client, this packet turned out to belong
// to the fixed-offset family after all despite the length prefix, and needs
// the same truncate/zero-pad treatment as its siblings.
//
// Approach: scan the raw payload for every position that looks like
// [u32 length][utf-8 bytes][0x00] where the utf-8 bytes are a single,
// complete, maximal run of hiragana/katakana/common-kanji (JapaneseRunLength)
// exactly `length - 1` bytes long. That combination -- an exact numeric
// length match on top of a well-formed Japanese run terminated by a null
// right where the length says it should be -- is specific enough that it
// won't misfire on ordinary binary stats data. No modeling of the
// surrounding per-entry stat fields was needed (or attempted) to find every
// name reliably.
//
// On a match, the name is translated and the length prefix is rewritten to
// the translated name's actual new byte count -- no truncation, since (per
// the architecture above) the length prefix is what tells the client how
// far to advance, not a fixed slot width.
//
// Names are resolved the same way every other player-chosen name in this
// codebase is: m00 'local_player_names' dict first, romaji fallback when
// the name isn't in the dict.
//
// Sample: docs/packets/references/monster_tavern_list (17/32 slots filled)
public sealed class MonsterTavernListPacket : IPacket
{
    private const int MinNameLength = 4;   // 1 utf-8 byte + null terminator, generous floor
    private const int MaxNameLength = 128; // generous ceiling; longest seen in sample was 19

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MonsterTavernListPacket(byte[] payloadData, PacketDependencies deps)
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
            if (TryReadNameField(_raw, i, out var fieldLen, out var text))
            {
                var newName = ResolveName(text, dict);
                if (newName != text)
                {
                    changed = true;
                    var newBytes = Encoding.UTF8.GetBytes(newName);
                    writer.WriteU32((uint)(newBytes.Length + 1)); // +1 for null terminator
                    writer.WriteBytes(newBytes);
                    writer.WriteU8(0);
                }
                else
                {
                    writer.WriteBytes(_raw.AsSpan(i, 4 + fieldLen).ToArray());
                }

                i += 4 + fieldLen;
            }
            else
            {
                writer.WriteU8(_raw[i]);
                i++;
            }
        }

        if (!changed) return;
        ModifiedData = writer.Build();
    }

    // Recognises `[u32 length][name bytes][0x00]` starting at `start`, where
    // `length` is the name's utf-8 byte count including the null terminator
    // and the name bytes are a single, complete, maximal Japanese run (see
    // class doc comment for why this combination is specific enough to
    // trust). `fieldLen` on success is `length` (i.e. name bytes + null,
    // NOT including the 4-byte length prefix itself).
    private static bool TryReadNameField(byte[] data, int start, out int fieldLen, out string text)
    {
        fieldLen = 0;
        text = "";

        if (start + 4 > data.Length) return false;
        var length = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(start, 4));
        if (length < MinNameLength || length > MaxNameLength) return false; // length excludes the u32 itself

        var nameStart = start + 4;
        if (nameStart + length > data.Length) return false;

        var strBytes = (int)length - 1; // minus null terminator
        if (strBytes <= 0) return false;
        if (data[nameStart + strBytes] != 0) return false;

        var runLen = JapaneseRunLength(data, nameStart);
        if (runLen != strBytes) return false;

        text = Encoding.UTF8.GetString(data, nameStart, strBytes);
        fieldLen = (int)length;
        return true;
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
        (codepoint >= 0x3040 && codepoint <= 0x30FF) || // hiragana + katakana
        (codepoint >= 0x4E00 && codepoint <= 0x9FFF);   // common kanji

    private string ResolveName(string japanese, Dictionary<string, string> dict)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        if (dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known)) return known;
        return _deps.Romanizer.ToRomaji(japanese);
    }
}
