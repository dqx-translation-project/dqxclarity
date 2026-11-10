using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The Tombola (ふくびき) prize list -- opcode 0x75, marker 0x0e23. Always ten
// prizes in the captures so far.
//
// Layout (after opcode + marker):
//   header        24 bytes (passthrough -- 8 zero bytes, u32 0x10, u32 0,
//                 a tick/id-looking u32, u32 0; meaning not confirmed)
//   prize_count   u32 (10)
//   prize_count x {
//     slot_id     u32 -- sequential (21..30 in the sample)
//     name        cstring (utf-8, null-terminated, no length prefix)
//     item_count  u32 -- number of item ids that follow (2 for the house kit,
//                 1 for everything else in the sample)
//     item_ids    item_count x u32
//     qty_count   u32 -- matched item_count in every entry of the sample
//     quantities  qty_count x u32
//   }
//   nothing trails the last entry.
//
// Names are sequential null-terminated strings with no fixed-width slot and no
// length prefix, so the packet is rebuilt with the translated names at their
// natural length; every other byte is copied through unchanged.
//
// The parse is strict: if the counts don't line up or the last entry doesn't
// end exactly at the end of the packet, PacketLayoutException is thrown and
// PacketGuard sends the original packet to the game and files a mismatch report.
//
// Names are looked up in m00 'custom_lottery_prizes' first (curated names for
// prizes that aren't plain items, e.g. お好きな家キット), then 'items'. No
// machine translation or romaji fallback -- a miss stays Japanese.
//
// Sample: 0x75 0x0E23 capture from 2026-11-10 (10 prizes: お好きな家キット,
//         キラゴルドコイン, ヘルクラウダーコイン, 破壊神フォロボスコイン,
//         はぐメタコイン, メタスラコイン, ゴールドストーン, まほうのせいすい,
//         まほうの小ビン, ふくびき補助券).
public sealed class TombolaPrizeListPacket : IPacket
{
    private const int HeaderBytes = 24;
    private const int MaxPrizes = 64;      // sanity cap; ten in practice
    private const int MaxIdsPerPrize = 64; // sanity cap; one or two in practice
    private const int MaxNameBytes = 256;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public TombolaPrizeListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        // ── Parse: record where each name sits; everything else is copied as-is ──
        var names = new List<(int Start, int Length, string Text)>();
        var reader = new PacketReader(_raw);

        reader.ReadBytesStrict(HeaderBytes, "tombola header");
        var count = ReadCount(ref reader, "prize count", MaxPrizes);

        for (var i = 0; i < count; i++)
        {
            reader.ReadBytesStrict(4, $"prize {i + 1} slot id");

            var nameStart = reader.Position;
            var name = reader.ReadCStringStrict($"prize {i + 1} name", MaxNameBytes);
            names.Add((nameStart, reader.Position - 1 - nameStart, name)); // length excludes the null

            var itemCount = ReadCount(ref reader, $"prize {i + 1} item count", MaxIdsPerPrize);
            reader.ReadBytesStrict(itemCount * 4, $"prize {i + 1} item ids");

            var qtyCount = ReadCount(ref reader, $"prize {i + 1} quantity count", MaxIdsPerPrize);
            reader.ReadBytesStrict(qtyCount * 4, $"prize {i + 1} quantities");
        }

        if (!reader.AtEnd)
            throw new PacketLayoutException(
                $"{reader.Remaining} unexpected bytes after the last prize at offset {reader.Position}", reader.Position);

        // ── Translate ──
        var customDict = _deps.M00Dict("custom_lottery_prizes");
        var itemDict = _deps.M00Dict("items");

        var replacements = new string?[names.Count];
        var changed = false;
        for (var i = 0; i < names.Count; i++)
        {
            var text = names[i].Text;
            if (!Translator.IsTextJapanese(text)) continue; // already English

            string? resolved = null;
            if (customDict.TryGetValue(text, out var c) && !string.IsNullOrEmpty(c)) resolved = c;
            else if (itemDict.TryGetValue(text, out var it) && !string.IsNullOrEmpty(it)) resolved = it;

            if (resolved == null || resolved == text) continue;
            replacements[i] = resolved;
            changed = true;
        }
        if (!changed) return;

        // ── Rebuild ──
        var writer = new PacketWriter();
        var pos = 0;
        for (var i = 0; i < names.Count; i++)
        {
            var (start, length, _) = names[i];
            writer.WriteBytes(_raw.AsSpan(pos, start - pos)); // bytes before this name
            if (replacements[i] is { } en)
                writer.WriteBytes(Encoding.UTF8.GetBytes(en));
            else
                writer.WriteBytes(_raw.AsSpan(start, length));
            pos = start + length; // the null terminator is copied with the next chunk
        }
        writer.WriteBytes(_raw.AsSpan(pos));

        ModifiedData = writer.Build();
    }

    private static int ReadCount(ref PacketReader reader, string what, int max)
    {
        if (reader.Remaining < 4)
            throw new PacketLayoutException($"{what}: no room at offset {reader.Position}", reader.Position);
        var at = reader.Position;
        var value = reader.ReadU32();
        if (value > (uint)max)
            throw new PacketLayoutException($"{what}: {value} at offset {at} is more than the {max} allowed", at);
        return (int)value;
    }
}
