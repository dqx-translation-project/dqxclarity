using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// An individual alliance member's detail/stats snapshot -- opcode 0x03,
// same as AllianceMemberListPacket, but a different marker (0xa7aa vs.
// 0x8f8f) and a completely different, fixed-size layout: all 4 sample
// captures on file (four different alliance members, シンディ/くろノコ/
// パンジィ/あ～にゃ, captured at different times) are exactly 786 bytes,
// byte-for-byte the same total length despite differing name and stat
// content throughout. Confirms the user's hypothesis that this "works in
// tandem with" the roster list packet -- one of these appears to accompany
// each member's entry, most likely carrying whatever per-member detail
// (stats, position, etc.) doesn't fit in the list packet's own per-record
// slot.
//
// The member's name is a cstring at a FIXED byte offset (Data offset 0x50)
// in all 4 captures -- given the packet's total length never varies at all
// between captures, this belongs to the fixed-offset "roster" family (see
// PartyInvitationPacket/AllianceMemberListPacket/TeamJoinMessagePacket's
// doc comments for the confirmed crash class those packets hit when a
// translated name is allowed to change a record's length), not the
// self-describing-length family EntityPacket/MonsterTavernListPacket/
// MonsterFarmListPacket use.
//
// BUG FOUND (あ～にゃ capture): this originally used the same generic
// whole-payload byte scan as AllianceMemberListPacket -- scan for maximal
// runs of valid 3-byte UTF-8 sequences that decode into the hiragana/
// katakana/common-kanji codepoint ranges (JapaneseRunLength), translate
// each run found, truncated/zero-padded to fit exactly where that run
// was. That works fine when a name is ONE unbroken run, but "あ～にゃ"
// contains a fullwidth tilde (U+FF5E) in the middle, which is outside
// those codepoint ranges -- so the scanner saw it as THREE pieces: a
// Japanese run ("あ"), a passthrough non-Japanese byte sequence ("～"),
// and a second Japanese run ("にゃ"). Each Japanese run got translated and
// zero-padded to its OWN original width independently: "あ" (3 bytes)
// romanized to "A", which with the \x04 prefix is only 2 bytes, so it was
// padded with one 0x00 to fill the original 3-byte slot -- landing a NUL
// byte in the MIDDLE of the name, right after "A" and before "～にゃ". The
// game's cstring reader stops at the first 0x00 it sees regardless of
// intent, so it rendered "A" and silently dropped everything after. This
// only ever looked safe in the first 3 samples because none of those names
// contained non-Japanese punctuation, so each was a single run spanning
// the whole field and any zero-padding landed exactly where the real
// terminator already was.
//
// Fix: don't scan for same-script runs across the payload. The name field
// lives at a known, fixed, confirmed offset (0x50), so read it as ONE
// atomic null-terminated cstring, translate the WHOLE string (embedded
// punctuation and all) as a single unit, and truncate/zero-pad against the
// ORIGINAL name's total byte length -- never per sub-run. The original
// terminator's position never moves and is always re-written explicitly,
// so a padding NUL can only ever land where the real terminator already
// was, never earlier.
//
// NOTE: AllianceMemberListPacket, TeamJoinMessagePacket, and
// CharacterLogListPacket all still use the generic whole-payload run-scan
// approach this bug was found in, and are exposed to the identical failure
// mode for any name containing similar embedded non-hiragana/katakana/
// kanji punctuation (fullwidth tilde, fullwidth "!"/"?", hearts, etc. --
// note U+30FB middle dot and U+30FC prolonged sound mark are themselves
// IN the scanned range so those specifically are fine). Not yet audited or
// fixed there -- worth revisiting.
//
// The resolved name is written with a leading \x04 byte (see Build) --
// same trick used for AllianceMemberListPacket and EntityPacket's
// Player/Party kinds -- to stop the game from rendering a GM-face icon next
// to the translated name.
//
// Two 4-byte fields bracket the packet (Data offset 0x08 and near the very
// end) that look like the "doubled tick/id" pattern seen elsewhere in this
// codebase, but their exact meaning is NOT confirmed: in the シンディ capture
// both copies matched each other; in the くろノコ and パンジィ captures
// (taken 1ms apart, evidently the same alliance-viewing batch) the leading
// copy was IDENTICAL between the two members while the trailing copy
// differed per member. Best guess is something like an alliance/viewing
// session id up front and a per-member character id at the end, but this
// is genuinely unverified -- flagging rather than guessing further.
//
// Names are resolved the same way every other player-chosen name in this
// codebase is: m00 'local_player_names' dict first, romaji fallback when
// the name isn't in the dict.
//
// Samples: docs/packets/references/alliance_member_detail_1 (シンディ),
//          docs/packets/references/alliance_member_detail_2 (くろノコ),
//          docs/packets/references/alliance_member_detail_3 (パンジィ),
//          docs/packets/references/alliance_member_detail_4 (あ～にゃ)
public sealed class AllianceMemberDetailPacket : IPacket
{
    // Confirmed across all 4 samples on file: the member's name cstring
    // always starts here.
    private const int NameFieldOffset = 0x50;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public AllianceMemberDetailPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < NameFieldOffset) return;

        var reader = new PacketReader(_raw);
        var header = reader.ReadBytes(NameFieldOffset).ToArray();
        var name = reader.ReadCString();
        // Everything after the terminator ReadCString just consumed --
        // padding out to the fixed record size, plus the rest of the
        // packet. Passed through byte-for-byte untouched.
        var rest = reader.RemainingBytes().ToArray();

        // Already translated -- hook re-intercepted its own modified write.
        if (!Translator.IsTextJapanese(name)) return;

        var dict = _deps.M00Dict("local_player_names");
        var resolved = dict.TryGetValue(name, out var known) && !string.IsNullOrEmpty(known)
            ? known
            : _deps.Romanizer.ToRomaji(name);

        if (string.IsNullOrEmpty(resolved) || resolved == name) return;

        // \x04 prefix keeps the game from showing the GM-face icon next to the
        // translated name -- same trick AllianceMemberListPacket/EntityPacket
        // use.
        var newBytes = Encoding.UTF8.GetBytes("\x04" + resolved);

        // Fixed-width slot: the ORIGINAL name's total byte length (the
        // whole cstring, not any sub-run of it -- see the class doc
        // comment for why per-run padding corrupted names containing
        // embedded punctuation). Truncate if the translation is longer;
        // zero-pad if shorter. Either way the original terminator is
        // re-written explicitly at its original position, so this can
        // never change the packet's total length.
        var originalNameBytes = Encoding.UTF8.GetByteCount(name);
        if (newBytes.Length > originalNameBytes) newBytes = newBytes[..originalNameBytes];

        var writer = new PacketWriter();
        writer.WriteBytes(header);
        writer.WriteBytes(newBytes);
        writer.WriteBytes(new byte[originalNameBytes - newBytes.Length]); // zero-pad up to the terminator's original position
        writer.WriteU8(0); // the original terminator, unmoved
        writer.WriteBytes(rest);
        ModifiedData = writer.Build();
    }
}
