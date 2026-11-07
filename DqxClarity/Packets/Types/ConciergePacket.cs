using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The Concierge (the NPC you set up in your house/shrine) -- opcode 0x05,
// marker 0x2B66. Translates the concierge's name and the owner's (the player's) name.
//
// Layout (after opcode + marker):
//   header               251 bytes (passthrough) -- 221 before 8.1
//   name                 cstring (utf-8) -- the concierge's name
//   owner name           cstring (utf-8) -- the player's character name; an
//                        empty string (a lone null) in the pre-8.1 capture
//   remaining            (passthrough) -- the greeting messages etc.
//
// The concierge's name is looked up in the m00 dict {custom_concierge_mail_names,
// local_mytown_names}; if missing we fall back to the romanizer. We prepend
// '\x04' to the new name to suppress the GM-face icon the game shows for
// unknown senders.
//
// The owner's name is resolved the way every other player name is: m00
// 'local_player_names' first, romaji fallback (10 characters at most). It is
// shown in a plain text box, so it gets no '\x04' prefix.
//
// THE NAME IS WRITTEN AS A VARIABLE-LENGTH CSTRING, exactly as before 8.1 --
// the rest of the packet follows it unchanged, shifted by however much the
// name's length changed. Do not turn this into a fixed-slot, zero-padded
// in-place patch. An earlier attempt did, on the assumption that the name has
// a fixed-size slot, and the game crashed every time the packet was altered
// (no mismatch was reported). Both before and after 8.1 the strings run
// back to back with no padding between them: name\0, the owner's name\0
// (an empty string, just a lone null, in the pre-8.1 capture), then the first
// message. That is what a client reading consecutive cstrings expects;
// padding the name with zeros makes it read an empty owner name and every
// field after it from the wrong place. The same goes for the owner's name. Since the pre-8.1 version of this
// class worked with the variable-length write, the only thing that 8.1
// changed for it is the header size.
//
// Samples: docs/packets/references/concierge (pre-8.1, name at 221),
//          concierge_2 (8.1, name at 251)
public sealed class ConciergePacket : IPacket
{
    private const int HeaderBytes = 251;
    private const int OwnerMaxRomaji = 10;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public ConciergePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        var nameEnd = _raw.Length > HeaderBytes ? Array.IndexOf(_raw, (byte)0, HeaderBytes) : -1;
        if (nameEnd < 0)
            throw new PacketLayoutException(
                $"Concierge packet is {_raw.Length} bytes; no name string after the {HeaderBytes}-byte header", HeaderBytes);

        var ownerStart = nameEnd + 1;
        var ownerEnd = ownerStart < _raw.Length ? Array.IndexOf(_raw, (byte)0, ownerStart) : -1;
        if (ownerEnd < 0)
            throw new PacketLayoutException(
                $"Concierge packet has no owner name string after the name (name ends at {nameEnd})", ownerStart);

        if (!PacketText.TryDecode(_raw.AsSpan(HeaderBytes, nameEnd - HeaderBytes), out var name))
            throw new PacketLayoutException("Concierge name does not hold text", HeaderBytes);

        var newName = TranslateConciergeName(name);
        var newOwner = PacketText.TryDecode(_raw.AsSpan(ownerStart, ownerEnd - ownerStart), out var owner)
            ? TranslateOwnerName(owner)
            : null;

        if (newName == null && newOwner == null) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_raw[..HeaderBytes]);
        WriteString(writer, newName, _raw, HeaderBytes, nameEnd);
        WriteString(writer, newOwner, _raw, ownerStart, ownerEnd);
        writer.WriteBytes(_raw[(ownerEnd + 1)..]);
        ModifiedData = writer.Build();
    }

    // Writes the new string, or the original bytes when there is no new one,
    // followed by the null terminator.
    private static void WriteString(PacketWriter writer, string? text, byte[] raw, int start, int end)
    {
        if (text != null) writer.WriteCString(text);
        else
        {
            writer.WriteBytes(raw[start..end]);
            writer.WriteBytes(new byte[1]);
        }
    }

    // New concierge name (with the \x04 prefix), or null to leave it alone.
    private string? TranslateConciergeName(string name)
    {
        // Empty, or already english (re-intercepted write / non-jp client).
        if (name.Length == 0 || !Translator.IsTextJapanese(name)) return null;

        var dict = _deps.M00Dict("custom_concierge_mail_names", "local_mytown_names");
        var translated = dict.TryGetValue(name, out var en) && !string.IsNullOrEmpty(en)
            ? en
            : _deps.Romanizer.ToRomaji(name);

        return translated == name ? null : "\x04" + translated;
    }

    // New owner name (no prefix), or null to leave it alone.
    private string? TranslateOwnerName(string owner)
    {
        if (owner.Length == 0 || !Translator.IsTextJapanese(owner)) return null;

        var dict = _deps.M00Dict("local_player_names");
        var translated = dict.TryGetValue(owner, out var en) && !string.IsNullOrEmpty(en)
            ? en
            : _deps.Romanizer.ToRomaji(owner, OwnerMaxRomaji);

        return string.IsNullOrEmpty(translated) || translated == owner ? null : translated;
    }
}
