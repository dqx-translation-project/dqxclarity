using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The map's NPC list -- opcode 0x5c, marker 0x0bf6. (Formerly SiblingNamePacket.)
// It's sent when the map is opened and lists only the NPCs whose names are
// GENERATED rather than coming from the game's own files: the player's
// sibling, and My Town amenity staff named by the player (紹介人ショウブ,
// 取引商ラクラン, シスター・クリスタ, ...). Fixed NPC names aren't in it.
// (It was first taken for a one-off "sibling name" packet because the only
// early capture had a single entry: the sibling, カッタ.)
//
// Layout (after opcode + marker):
//   header        16 bytes -- u32 1, u32 0, u32 (0xA52 in the 13-entry
//                 capture, 1925 in the sibling one), u32 entry_count
//   entry_count x {
//     id          u32 (sequential-ish, e.g. 0x1D44..)
//     flags       4 bytes (00 FF 01 00 in every entry so far)
//     npc_id      u32 (0x9C40..0x9C70 in the sample)
//     x, y        2 x float -- position on the map
//     name        cstring (utf-8, null-terminated, no length prefix)
//   }
//   nothing trails the last entry.
//
// Names are sequential null-terminated strings with no fixed slot, so each is
// rewritten at its natural length; every other byte is copied through. The
// parse is strict: if the count doesn't line up or bytes are left over,
// PacketLayoutException makes PacketGuard pass the original packet through
// and file a mismatch report.
//
// Each name is resolved in order:
//   1. exact entry in m00 'custom_concierge_mail_names' / 'local_mytown_names'
//      (amenity staff overrides, same as MyTownAmenityPacket)
//   2. exact entry in 'local_player_names' (the sibling, set at character creation)
//   3. title template (MyTownNameTemplate: 紹介人ショウブ -> "Introducer " + romaji)
//   4. whole-name romaji, only if the result has no Japanese left (kana-only
//      names such as the sibling's)
//   otherwise left as-is.
//
// Samples: docs/packets/references/sibling_name (1 entry, カッタ); a 13-entry
// My Town capture from 2026-11-14.
public sealed class MapNpcListPacket : IPacket
{
    private const int HeaderBytes = 16;
    private const int CountOffset = 12;
    private const int EntryFixedBytes = 20;
    private const int MaxEntries = 256;
    private const int MaxNameBytes = 256;
    private const int RomajiCap = 25;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MapNpcListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        // ── Parse: record where each name sits ──
        var reader = new PacketReader(_raw);
        reader.ReadBytesStrict(CountOffset, "map npc list header");
        var countAt = reader.Position;
        if (reader.Remaining < 4)
            throw new PacketLayoutException($"entry count: no room at offset {countAt}", countAt);
        var count = reader.ReadU32();
        if (count > MaxEntries)
            throw new PacketLayoutException($"entry count {count} at offset {countAt} is more than {MaxEntries}", countAt);

        var names = new List<(int Start, int Length, string Text)>();
        for (var i = 0; i < count; i++)
        {
            reader.ReadBytesStrict(EntryFixedBytes, $"entry {i + 1} fields");
            var start = reader.Position;
            var name = reader.ReadCStringStrict($"entry {i + 1} name", MaxNameBytes);
            names.Add((start, reader.Position - 1 - start, name)); // length excludes the null
        }

        if (!reader.AtEnd)
            throw new PacketLayoutException(
                $"{reader.Remaining} unexpected bytes after the last entry at offset {reader.Position}", reader.Position);

        // ── Translate ──
        var replacements = new string?[names.Count];
        var changed = false;
        for (var i = 0; i < names.Count; i++)
        {
            var resolved = ResolveName(names[i].Text);
            if (resolved == null) continue;
            replacements[i] = resolved;
            changed = true;
        }
        if (!changed) return;

        // ── Rebuild: copy everything, swapping in translated names ──
        var writer = new PacketWriter();
        var pos = 0;
        for (var i = 0; i < names.Count; i++)
        {
            var (start, length, _) = names[i];
            writer.WriteBytes(_raw.AsSpan(pos, start - pos));
            if (replacements[i] is { } en)
                writer.WriteBytes(Encoding.UTF8.GetBytes(en));
            else
                writer.WriteBytes(_raw.AsSpan(start, length));
            pos = start + length; // the null terminator is copied with the next chunk
        }
        writer.WriteBytes(_raw.AsSpan(pos));

        ModifiedData = writer.Build();
    }

    // The English name, or null to leave this entry untouched.
    private string? ResolveName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return null;

        var myTownDict = _deps.M00Dict("custom_concierge_mail_names", "local_mytown_names");
        if (myTownDict.TryGetValue(japanese, out var town) && !string.IsNullOrEmpty(town))
            return town == japanese ? null : town;

        var playerDict = _deps.M00Dict("local_player_names");
        if (playerDict.TryGetValue(japanese, out var player) && !string.IsNullOrEmpty(player))
            return player == japanese ? null : player;

        if (MyTownNameTemplate.TryTranslate(japanese, _deps.Romanizer, RomajiCap) is { } templated)
            return templated;

        var romaji = _deps.Romanizer.ToRomaji(japanese, RomajiCap);
        return string.IsNullOrWhiteSpace(romaji) || romaji == japanese || Translator.IsTextJapanese(romaji)
            ? null
            : romaji;
    }
}
