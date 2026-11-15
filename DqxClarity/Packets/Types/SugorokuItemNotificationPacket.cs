using System.Buffers.Binary;
using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// A generic "notification with up to two strings" packet -- opcode 0x95,
// marker 0xC9E3. First seen as Sugoroku (the board-game minigame)'s "you won
// an item" notification, naming the winning player and the item. It is ALSO
// used for other notifications whose first string is not a player name at
// all -- e.g. a Trainee Logbook title ("釣りの求道者！") with no second string.
//
// Layout (after opcode + marker):
//   header           12 bytes -- passthrough. Third u32 looks like a
//                    notification type: 0x151 (337) in both Sugoroku item
//                    captures, 0x43F (1087) in the Trainee Logbook capture.
//                    Unconfirmed, so it isn't relied on.
//   text1_len        u32 -- byte length of text1 INCLUDING its null terminator
//   text1            utf-8 string + null (player name for Sugoroku; logbook /
//                    episode-request text otherwise)
//   text2_len        u32 -- same shape. 0 in the logbook capture, in which
//                    case no string bytes follow AT ALL (not even a null).
//   text2            utf-8 string + null (item name for Sugoroku), or absent
//   (anything left over is passed through untouched)
//
// Both strings are length-prefixed, so a translated string is free to grow or
// shrink. Each field is read by its length prefix, and a field that isn't
// translated is copied back byte-for-byte -- so a zero-length text2 stays
// exactly "00 00 00 00". (An earlier version re-encoded every field, which
// turned that into "01 00 00 00 00": a length of 1 plus an extra null byte.)
//
// Translation:
//   text1 : m00 'custom_trainee_logbook', then 'custom_episode_request_book'
//           (curated notification text is checked before names), then
//           'local_player_names'. The romaji fallback is used ONLY when text2
//           is present -- i.e. the Sugoroku "player won item" shape, where
//           text1 really is a player name. Without that gate a logbook title
//           missing from the dictionaries got romanized into "釣rino求道者".
//   text2 : m00 'items' only, no romaji fallback; a miss stays Japanese.
//
// Samples: two Sugoroku captures (player トギ winning 幻界闘士のゆびわ and
// ドット風エステラ像); one Trainee Logbook capture (釣りの求道者！, text2_len 0,
// 2026-11-11).
public sealed class SugorokuItemNotificationPacket : IPacket
{
    private const int HeaderBytes = 12;
    private const int MaxStringBytes = 4096;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public SugorokuItemNotificationPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < HeaderBytes + 4) return;

        var pos = HeaderBytes;
        var field1 = ReadField(ref pos, "text1");
        var field2 = pos + 4 <= _raw.Length ? ReadField(ref pos, "text2") : (Field?)null;
        var remainderStart = pos;

        var hasText2 = field2 is { Text.Length: > 0 };
        var new1 = ResolveText1(field1.Text, allowRomaji: hasText2);
        var new2 = field2 is { } f2 ? ResolveItemName(f2.Text) : null;

        var changed1 = new1 != field1.Text;
        var changed2 = field2 is { } f && new2 != f.Text;
        if (!changed1 && !changed2) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_raw.AsSpan(0, HeaderBytes));
        WriteField(writer, field1, changed1 ? new1 : null);
        if (field2 is { } g) WriteField(writer, g, changed2 ? new2 : null);
        writer.WriteBytes(_raw.AsSpan(remainderStart));
        ModifiedData = writer.Build();
    }

    // A length-prefixed string field: where it starts (at the u32), how many
    // bytes it spans in total (u32 + string bytes), and its decoded text.
    private readonly record struct Field(int Start, int Span, string Text);

    private Field ReadField(ref int pos, string what)
    {
        if (pos + 4 > _raw.Length)
            throw new PacketLayoutException($"{what}: no room for a length field at offset {pos}", pos);

        var start = pos;
        var len = BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(pos, 4));
        pos += 4;

        if (len == 0) return new Field(start, 4, ""); // absent string: nothing follows

        if (len > MaxStringBytes || len > (uint)(_raw.Length - pos))
            throw new PacketLayoutException($"{what}: length {len} at offset {start} doesn't fit", start);
        if (_raw[pos + (int)len - 1] != 0)
            throw new PacketLayoutException($"{what}: the {len}-byte string at offset {pos} doesn't end in a null", start);

        var text = Encoding.UTF8.GetString(_raw, pos, (int)len - 1);
        pos += (int)len;
        return new Field(start, pos - start, text);
    }

    // Untranslated fields are copied back exactly as they arrived.
    private void WriteField(PacketWriter writer, Field field, string? replacement)
    {
        if (replacement == null)
        {
            writer.WriteBytes(_raw.AsSpan(field.Start, field.Span));
            return;
        }

        var bytes = Encoding.UTF8.GetBytes(replacement);
        writer.WriteU32((uint)(bytes.Length + 1)); // +1 for the null terminator
        writer.WriteBytes(bytes);
        writer.WriteU8(0);
    }

    private string ResolveText1(string japanese, bool allowRomaji)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;

        foreach (var file in new[] { "custom_trainee_logbook", "custom_episode_request_book", "local_player_names" })
        {
            var dict = _deps.M00Dict(file);
            if (dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known)) return known;
        }

        // Only the Sugoroku shape (an item name follows) is known to carry a
        // player name here; anything else that missed the dictionaries stays Japanese.
        return allowRomaji ? _deps.Romanizer.ToRomaji(japanese) : japanese;
    }

    // No romaji fallback -- a miss passes through as the original Japanese
    // untouched, same as every other item-name lookup in this codebase.
    private string ResolveItemName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        var dict = _deps.M00Dict("items");
        return dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known) ? known : japanese;
    }
}
