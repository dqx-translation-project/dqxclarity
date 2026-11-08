using System.Text;

namespace DqxClarity.Packets.Types;

// NPC chat-bubble text -- the short line(s) shown in the speech-bubble-style
// popup during certain NPC interactions/events (distinct from CornerTextPacket,
// marker 0x19be, which covers minigame hints and combat "chat" taunts shown
// in the screen corner -- this is marker 0x9ade instead).
//
// Layout (after opcode + marker):
//   header   20 bytes (passthrough -- Data[0] is the only byte observed to
//            differ across captures, which looks like a per-message
//            counter/sequence byte; Data[1:8] was all zero in every capture;
//            Data[8:10] was constant 17 9F; Data[10:20] was constant
//            00 04 35 00 00 00 00 00 00 00 -- none of it is needed to
//            translate the text, so it's left fully opaque, same treatment
//            CornerTextPacket gives its header)
//   text     cstring (utf-8, null-terminated -- NOT length-prefixed, unlike
//            CornerTextPacket/NpcDialoguePacket; the client evidently just
//            reads up to the null terminator)
//   tail     remaining bytes, padding this packet out to a FIXED TOTAL SIZE
//            (see below). Its CONTENT is not meaningful -- it's stale
//            leftover content from a reused fixed-size buffer that never
//            gets cleared past the new string's null terminator. Proof: in
//            one capture, decoding the bytes immediately after the first
//            null hits an invalid UTF-8 start byte (a continuation byte
//            where a lead byte is required), which is only possible if
//            that's leftover garbage from a longer previous message rather
//            than intentional data; in another, shorter-message capture,
//            the tail is just zero padding.
//
//            BUT the packet's total LENGTH is load-bearing even though the
//            tail's content isn't: every original capture of this marker is
//            the exact same fixed size on the wire, and translating one to a
//            *different* total size crashed the client (confirmed against
//            the live game -- translated packets with total sizes like 8190
//            or 8209 instead of the original 8222 broke it). So Build()
//            below keeps the total output length pinned to _raw.Length no
//            matter how long the translated text is, by growing/shrinking
//            only the opaque tail (zero-padding if the new text is shorter,
//            trimming the tail if it's longer) -- never by changing the
//            packet's overall size the way CornerTextPacket is allowed to.
//
// Looked up verbatim in m00 'custom_corner_text' (same source CornerTextPacket
// draws from) per explicit instruction; misses pass through as the original
// Japanese -- NOT machine translated, matching CornerTextPacket's policy for
// this same curated, fixed-size dictionary (not freeform prose).
//
// Samples: docs/packets/references/npc_chat_bubble,
//          docs/packets/references/npc_chat_bubble_2 (confirms the header's
//          constant bytes and the stale-buffer-garbage tail across two
//          different messages -- NOTE: both sample files are truncated
//          excerpts, shorter than the real fixed ~8222-byte wire size; they
//          only demonstrate the header/text layout, not the true total
//          length this class must preserve)
public sealed class NpcChatBubblePacket : IPacket
{
    private const int HeaderBytes = 20;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _text = "";
    private byte[] _tail = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public NpcChatBubblePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes) return;
        var reader = new PacketReader(_raw);
        _header = reader.ReadBytes(HeaderBytes).ToArray();
        _text = reader.ReadCString();
        _tail = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var dict = _deps.M00Dict("custom_corner_text");
        if (!dict.TryGetValue(_text, out var newText) || string.IsNullOrEmpty(newText)) return;
        if (newText == _text) return;

        var newTextBytes = Encoding.UTF8.GetBytes(newText);

        // Keep the total output size pinned to the original packet's size --
        // see the class doc comment for why. Only the opaque tail grows or
        // shrinks to absorb the difference; the header and text are never
        // truncated to make room.
        var available = _raw.Length - HeaderBytes - (newTextBytes.Length + 1);
        if (available < 0)
        {
            // Translated text (plus its null terminator) doesn't fit even
            // with the whole tail trimmed away. Emitting a packet with a
            // different total size crashes the client, so skip this
            // translation rather than risk that -- the player just sees the
            // original Japanese instead, which is safe.
            return;
        }

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(newText);
        if (available <= _tail.Length)
        {
            writer.WriteBytes(_tail[..available]);
        }
        else
        {
            writer.WriteBytes(_tail);
            writer.WriteBytes(new byte[available - _tail.Length]);
        }

        ModifiedData = writer.Build();
    }
}
