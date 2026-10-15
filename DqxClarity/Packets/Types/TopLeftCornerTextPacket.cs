using System.Text;

namespace DqxClarity.Packets.Types;

// The short status text shown in the TOP LEFT corner of the screen in certain
// situations -- opcode 0x03, marker 0x5477. Seen so far: the "go to the real
// Seledot mountain pass" style prompt (真のセレドット山道に行け！) and the
// 精神浸食中 / 精神浸食停止 (mind-erosion started / stopped) status line.
//
// NOT the same packet as CornerTextPacket (opcode 0x1f, marker 0x19be, the
// top-right minigame hint / combat chat line, which has a 12-byte header and a
// u32 text length). This one is a different packet that happens to feed the
// same custom_corner_text dictionary.
//
// Layout (after opcode + marker), from three captures:
//   header   8 bytes -- all zero in two captures, 02 00 00 00 00 00 00 00 in
//            the third (精神浸食停止, the "stopped" variant of 精神浸食中,
//            whose header is all zero), so the first byte looks like a
//            state/kind flag. Passthrough.
//   text     cstring (utf-8, null-terminated, no length prefix)
//   tail     1 byte -- 00 in every capture. Passthrough.
//
// Total Data length is 8 + len(text) + 1 + 1 (49, 21 and 24 bytes in the
// samples), so it genuinely varies with the text -- the client already
// accepts different lengths for this packet, which is why the translated text
// is simply written in place of the original (no fixed-width slot).
//
// Translation is a dictionary lookup only, and deliberately nothing else:
// the body is looked up verbatim in m00 'custom_corner_text'; on a hit the
// text is replaced, on a miss the packet is left completely alone (no
// machine translation, no romaji, no bad_strings). These are short, fixed
// system strings, so every one is expected to have a hand-written entry.
//
// Samples: docs/packets/references/top_left_corner_text_1 (真のセレドット
//          山道に行け！), top_left_corner_text_2 (精神浸食中) and
//          top_left_corner_text_3 (精神浸食停止)
public sealed class TopLeftCornerTextPacket : IPacket
{
    private const int HeaderBytes = 8;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _text = "";
    private byte[] _tail = Array.Empty<byte>();
    private bool _parsed;

    public byte[]? ModifiedData { get; private set; }

    public TopLeftCornerTextPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        // Need the header plus at least a terminator.
        if (_raw.Length < HeaderBytes + 1) return;

        var terminator = Array.IndexOf(_raw, (byte)0, HeaderBytes);
        if (terminator < 0) return; // unterminated text: not the shape we know

        _header = _raw[..HeaderBytes];
        _text   = Encoding.UTF8.GetString(_raw, HeaderBytes, terminator - HeaderBytes);
        _tail   = _raw[(terminator + 1)..];
        _parsed = true;
    }

    public void Build()
    {
        if (!_parsed || _text.Length == 0) return;

        var dict = _deps.M00Dict("custom_corner_text");
        if (!dict.TryGetValue(_text, out var english) || string.IsNullOrEmpty(english)) return;
        if (english == _text) return;

        var textBytes = Encoding.UTF8.GetBytes(english);

        var result = new byte[_header.Length + textBytes.Length + 1 + _tail.Length];
        var pos = 0;
        Buffer.BlockCopy(_header, 0, result, pos, _header.Length);
        pos += _header.Length;
        Buffer.BlockCopy(textBytes, 0, result, pos, textBytes.Length);
        pos += textBytes.Length;
        result[pos++] = 0; // terminator
        Buffer.BlockCopy(_tail, 0, result, pos, _tail.Length);

        ModifiedData = result;
    }
}
