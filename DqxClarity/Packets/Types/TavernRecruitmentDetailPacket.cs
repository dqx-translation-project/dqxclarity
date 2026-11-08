using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The tavern recruitment board's "view player details" screen -- opcode
// 0xAA, same as TavernRecruitmentListPacket but a different marker (0xE535
// vs. 0xDE02) and a completely different shape: one large (~8.3KB), mostly
// zero-padded packet describing a single player's full detail view, not a
// repeating list of records. The only thing translated is the player name;
// everything else (stats, equipment, whatever else fills out the rest of
// the packet) is unexamined and passed through untouched, per request --
// only the name was asked for.
//
// The name is a cstring at a FIXED offset (Data offset 0x30) in both sample
// captures ("エクサリン" and "ガブリソ" -- different players, different name
// lengths, same offset both times). A stable, unchanging 4-byte marker
// (06 01 00 01) was found starting at the same fixed offset (0x44) in both
// captures regardless of the name's length -- 0x44 - 0x30 = 20 bytes,
// implying the name lives in a fixed 20-byte reserved slot (cstring +
// zero-padding) ahead of that marker. This packet belongs to the same
// fixed-offset "roster" family as AllianceMemberDetailPacket and
// TavernRecruitmentListPacket (see their doc comments for the crash class
// fixed-offset-read packets hit when a translated name is allowed to change
// a record's length) -- so, same as those, the translated name is never
// allowed to change the packet's total length.
//
// Approach (identical technique to AllianceMemberDetailPacket, and for the
// same reason -- see that file's own doc comment for the bug a per-run
// scan approach hit when a name contains embedded non-kana punctuation):
// read the name as ONE atomic null-terminated cstring at the known offset,
// translate the whole string as a single unit, and truncate/zero-pad the
// replacement against the ORIGINAL name's byte length -- never hardcode
// the 20-byte slot width itself. The original terminator's position is
// always re-written explicitly, and everything after it (the rest of the
// slot's zero-padding, the 06 01 00 01 marker, and the remainder of the
// packet) is passed through byte-for-byte untouched, so the fixed 20-byte
// slot falls out naturally without this file needing to know its exact
// width.
//
// Unlike AllianceMemberListPacket/AllianceMemberDetailPacket, no \x04
// GM-face-icon-suppressing prefix is used here -- TavernRecruitmentListPacket,
// this packet's sibling in the same feature (the list this detail view
// accompanies), doesn't need one either, and nothing in the sample captures
// suggests this screen renders that icon next to a name.
//
// Names are resolved the same way every other player name in this codebase
// is: m00 'local_player_names' dict first, romaji fallback when the name
// isn't in the dict.
//
// Samples: two live captures, opcode 0xAA marker 0xE535, names "エクサリン"
// and "ガブリソ" -- no reference dump saved to docs/packets/references yet.
public sealed class TavernRecruitmentDetailPacket : IPacket
{
    // Confirmed in both sample captures: the player name cstring always
    // starts here.
    private const int NameFieldOffset = 0x30;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public TavernRecruitmentDetailPacket(byte[] payloadData, PacketDependencies deps)
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
        // Everything after the terminator ReadCString just consumed -- the
        // rest of the fixed-width slot's zero-padding, the 06 01 00 01
        // marker, and the remainder of this (large, mostly unexamined)
        // packet. Passed through byte-for-byte untouched.
        var rest = reader.RemainingBytes().ToArray();

        // Already translated -- hook re-intercepted its own modified write.
        if (!Translator.IsTextJapanese(name)) return;

        var dict = _deps.M00Dict("local_player_names");
        var resolved = dict.TryGetValue(name, out var known) && !string.IsNullOrEmpty(known)
            ? known
            : _deps.Romanizer.ToRomaji(name);

        if (string.IsNullOrEmpty(resolved) || resolved == name) return;

        var newBytes = Encoding.UTF8.GetBytes(resolved);

        // Fixed-width slot: the ORIGINAL name's total byte length. Truncate
        // if the translation is longer; zero-pad if shorter. Either way the
        // original terminator is re-written explicitly at its original
        // position, so this can never change the packet's total length.
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
