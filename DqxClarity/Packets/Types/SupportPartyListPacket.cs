using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   header                28 bytes (player_count u32 at offset 24)
//   member[player_count]: { entry_header 21 bytes, name 20-byte fixed slot }
//   tail                  4 bytes
//
// Names looked up in m00 'local_player_names' first; romanizer fallback on miss.
// Name slot is 20 bytes (19 usable + null terminator).
//
// The parse is strict: the members plus the 4-byte tail must account for the
// packet exactly, and every name slot must hold null-terminated text --
// otherwise PacketLayoutException makes PacketGuard pass the original through
// and file a mismatch report. (An earlier version read the count from a single
// byte, never checked the size, and romanized whatever was in each slot, so a
// layout change would have written romaji over binary data.) Only names that
// are Japanese and actually change are rewritten; bytes after the original
// name's terminator inside a slot (non-zero in the sample) are kept unless the
// new name needs the room. The name is cut on a utf-8 character boundary.
//
// Sample: docs/packets/references/support_party_list (3 members)
public sealed class SupportPartyListPacket : IPacket
{
    private const int HeaderBytes = 28;
    private const int PlayerCountOffsetInHeader = 24;
    private const int MemberEntryHeader = 21;
    private const int NameSlotBytes = 20;
    private const int TailBytes = 4;
    private const int MaxMembers = 16;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public SupportPartyListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        var reader = new PacketReader(_raw);
        reader.ReadBytesStrict(PlayerCountOffsetInHeader, "support party header");
        var count = reader.ReadCountStrict("member count", MaxMembers);
        if (count == 0) return;

        var expected = HeaderBytes + count * (MemberEntryHeader + NameSlotBytes) + TailBytes;
        if (_raw.Length != expected)
            throw new PacketLayoutException(
                $"{count} members should make a {expected}-byte packet, got {_raw.Length}", HeaderBytes);

        var dict = _deps.M00Dict("local_player_names");
        var patch = new PacketPatch(_raw);
        var pos = HeaderBytes;
        for (var i = 0; i < count; i++)
        {
            var slotAt = pos + MemberEntryHeader;
            pos = slotAt + NameSlotBytes;

            var slot = _raw.AsSpan(slotAt, NameSlotBytes);
            var nul = slot.IndexOf((byte)0);
            if (nul < 0)
                throw new PacketLayoutException($"member {i + 1} name slot has no terminator", slotAt);
            if (!PacketText.TryDecode(slot[..nul], out var name))
                throw new PacketLayoutException($"member {i + 1} name slot does not hold text", slotAt);

            if (name.Length == 0 || !Translator.IsTextJapanese(name)) continue;

            var translated = dict.TryGetValue(name, out var en) && !string.IsNullOrEmpty(en)
                ? en
                : _deps.Romanizer.ToRomaji(name, 11);
            if (string.IsNullOrEmpty(translated) || translated == name) continue;

            var bytes = Encoding.UTF8.GetBytes(PacketPatch.TruncateUtf8(translated, NameSlotBytes - 1));
            var newSlot = slot.ToArray();                 // keeps bytes after the old terminator
            var clearTo = Math.Max(nul, bytes.Length) + 1;
            Array.Clear(newSlot, 0, Math.Min(clearTo, NameSlotBytes));
            bytes.CopyTo(newSlot, 0);
            patch.Replace(slotAt, NameSlotBytes, newSlot);
        }

        if (patch.HasEdits) ModifiedData = patch.Build();
    }
}
