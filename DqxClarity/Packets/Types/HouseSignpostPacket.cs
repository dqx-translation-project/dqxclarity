using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The signpost outside a player's house -- opcode 0x05, marker 0x131e.
// Two points of interest, both confirmed across 2 captures (ゆめきちの家/
// ゆめきち and しぶやの家/しぶや):
//
//   house name    cstring at Data offset 0x20c (524) -- defaults to
//                 "<player name>の家" but can be freely renamed by the
//                 player to anything
//   player name   cstring at Data offset 0x3e0 (992) -- just the owner's
//                 name, no suffix
//
// Both offsets are identical across both captures despite the names
// differing in length (18/12 bytes vs. 15/9 bytes) -- and, tellingly, the
// two captures' TOTAL packet length is identical too (1056 bytes both
// times) despite that difference. That's conclusive proof of the
// fixed-total-length "roster" family (see AllianceMemberDetailPacket's doc
// comment for the あ～にゃ bug this same shape can hit), not something
// merely inferred from a single sample -- so each name is read as ONE
// atomic null-terminated cstring at its fixed offset and written back
// truncated/zero-padded to fit exactly where the ORIGINAL text was, never
// touching anything before or after it. Because the gap between the two
// fields is computed at runtime from wherever the house name's cstring
// actually ends (not hardcoded), this still works correctly regardless of
// the house name's own length.
//
// Player name: resolved with the same logic used everywhere else in this
// codebase for a player-chosen name -- m00 'local_player_names' dict
// first, romaji fallback on miss. No \x04 GM-face-icon prefix -- not
// requested for this packet.
//
// House name: per the user, ONLY translated when it still exactly matches
// the default, untouched pattern "<original japanese player name>の家" --
// in that case it becomes "<translated player name>'s House", reusing the
// exact same resolved player name computed above. Any custom house name
// (anything not matching that exact pattern) is left completely
// untouched, not translated at all.
//
// Samples: docs/packets/references/house_signpost (house: ゆめきちの家,
//          player: ゆめきち -- the default-pattern case)
//          docs/packets/references/house_signpost_2 (house: しぶやの家,
//          player: しぶや -- also the default-pattern case)
public sealed class HouseSignpostPacket : IPacket
{
    private const int HouseNameFieldOffset = 0x20C;
    private const int PlayerNameFieldOffset = 0x3E0;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public HouseSignpostPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < PlayerNameFieldOffset) return;

        var reader = new PacketReader(_raw);
        var header = reader.ReadBytes(HouseNameFieldOffset).ToArray();
        var houseName = reader.ReadCString();

        // Gap between the two fields, computed from wherever the house
        // name's cstring actually ended -- not hardcoded, so this still
        // works if the house name's length differs from this sample.
        var middleLen = PlayerNameFieldOffset - reader.Position;
        if (middleLen < 0) return; // house name ran past the player name's offset -- not the shape we expect
        var middle = reader.ReadBytes(middleLen).ToArray();

        var playerName = reader.ReadCString();
        var tail = reader.RemainingBytes().ToArray();

        // Already translated -- hook re-intercepted its own modified write.
        if (!Translator.IsTextJapanese(playerName)) return;

        var playerDict = _deps.M00Dict("local_player_names");
        var resolvedPlayerName = playerDict.TryGetValue(playerName, out var known) && !string.IsNullOrEmpty(known)
            ? known
            : _deps.Romanizer.ToRomaji(playerName);

        // Only translate the house name if it still exactly matches the
        // untouched default pattern -- anything else (a custom name) is
        // left completely alone.
        var newHouseName = houseName == playerName + "の家"
            ? resolvedPlayerName + "'s House"
            : houseName;

        if (resolvedPlayerName == playerName && newHouseName == houseName) return;

        var writer = new PacketWriter();
        writer.WriteBytes(header);
        WriteFixedWidthSlot(writer, houseName, newHouseName);
        writer.WriteBytes(middle);
        WriteFixedWidthSlot(writer, playerName, resolvedPlayerName);
        writer.WriteBytes(tail);
        ModifiedData = writer.Build();
    }

    // Writes `translated` truncated/zero-padded to fit exactly within
    // `original`'s byte width, followed by the terminator at its original
    // (unmoved) position -- see the class doc comment for why this packet
    // needs that instead of letting fields grow/shrink freely.
    private static void WriteFixedWidthSlot(PacketWriter writer, string original, string translated)
    {
        var originalBytes = Encoding.UTF8.GetByteCount(original);
        var newBytes = Encoding.UTF8.GetBytes(translated);
        if (newBytes.Length > originalBytes) newBytes = newBytes[..originalBytes];
        writer.WriteBytes(newBytes);
        writer.WriteBytes(new byte[originalBytes - newBytes.Length]); // zero-pad to original width
        writer.WriteU8(0); // original terminator, unmoved
    }
}
