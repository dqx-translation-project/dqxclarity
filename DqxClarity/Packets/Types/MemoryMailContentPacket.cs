using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The full text of a single Memory Mail letter -- opcode 0x97, marker
// 0x5816. This is what MemoryMailListPacket's preview entries open into:
// confirmed by cross-referencing the timestamp and mail-id fields between
// the two -- this packet's first capture (timestamp b00bf62f, id 0x01af)
// matches memory_mail_2's カササギ record exactly, and its second capture
// (timestamp f08c1432, id 0x01c6) matches memory_mail's ムーロン record
// exactly, both down to the sender name too.
//
// A genuinely variable-length packet, same "growable" family as
// MemoryMailListPacket/MailSenderNamePacket -- confirmed by round-tripping
// both captures byte-for-byte in a from-scratch parser (389 and 372 bytes
// of Data respectively) before writing this class.
//
// Layout (after opcode + marker):
//   header   35 bytes (passthrough -- a 4-byte flag matching the list
//            entry's record-header flag, 12 zero bytes, a 4-byte
//            timestamp matching the list entry's timestamp field, 4 more
//            zero bytes, a 2-byte counter that does NOT correlate with
//            the body's length [70 vs 336 bytes / 71 vs 319 bytes in the
//            two captures on file -- almost certainly an unrelated
//            sequence/transaction counter, incrementing by 1 between the
//            two captures here same as it does elsewhere in this
//            codebase], then 9 more zero bytes)
//   name     cstring (utf-8, null-terminated) -- the sender
//   body     cstring (utf-8, null-terminated) -- the FULL letter text
//            this time, not a truncated preview (see MemoryMailListPacket)
//   tail     4 bytes (passthrough -- a 2-byte mail id matching the list
//            entry's id field, then 2 zero bytes)
//
// name is resolved with the same three-dictionary-then-gated-romaji logic
// used throughout the mail packet family (MailSenderNamePacket,
// MailInboxViewPacket, MemoryMailListPacket): m00
// 'custom_concierge_mail_names' first, then npcs + custom_npc_name_overrides,
// then 'local_player_names', then Romanizer.ToRomaji as a last resort
// gated to <= MaxNameLength characters.
//
// body is looked up verbatim in m00 'custom_mail', same dictionary and
// same "exact match or leave it alone" rule as every other mail-body field
// in this codebase -- NOT machine translated. Unlike the list packet's
// truncated previews, this is the complete original text, so it's the one
// place in the mail family where a 'custom_mail' hit is actually likely.
//
// Samples: docs/packets/references/memory_mail_content (カササギ, the
//          full "岳都ガタラまで、お越しください" Tanabata letter -- the
//          same letter previewed in memory_mail_2's 8th record)
//          docs/packets/references/memory_mail_content_2 (ムーロン, the
//          full "夏の終わり" letter -- the same letter previewed in
//          memory_mail's 1st record)
public sealed class MemoryMailContentPacket : IPacket
{
    private const int HeaderBytes = 35;
    private const int TailBytes = 4;
    private const int MaxNameLength = 10;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MemoryMailContentPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < HeaderBytes + TailBytes) return;

        var reader = new PacketReader(_raw);
        var header = reader.ReadBytes(HeaderBytes).ToArray();
        var name = reader.ReadCString();
        var body = reader.ReadCString();

        if (reader.Remaining < TailBytes) return;
        var tail = reader.ReadBytes(TailBytes).ToArray();

        var conciergeDict = _deps.M00Dict("custom_concierge_mail_names");
        var npcDict = _deps.NpcNameDict();
        var playerDict = _deps.M00Dict("local_player_names");
        var mailDict = _deps.M00Dict("custom_mail");

        var resolvedName = ResolveMailName(name, conciergeDict, npcDict, playerDict, _deps.Romanizer);
        var resolvedBody = mailDict.TryGetValue(body, out var known) && !string.IsNullOrEmpty(known)
            ? known
            : body;

        if (resolvedName == name && resolvedBody == body) return;

        var writer = new PacketWriter();
        writer.WriteBytes(header);
        writer.WriteCString(resolvedName);
        writer.WriteCString(resolvedBody);
        writer.WriteBytes(tail);
        writer.WriteBytes(reader.RemainingBytes()); // nothing on file so far, but don't drop it if a future capture has more
        ModifiedData = writer.Build();
    }

    // Same three-dictionary-then-gated-romaji priority used across the
    // whole mail packet family.
    private static string ResolveMailName(
        string text,
        Dictionary<string, string> conciergeDict,
        Dictionary<string, string> npcDict,
        Dictionary<string, string> playerDict,
        IRomanizer romanizer)
    {
        if (string.IsNullOrEmpty(text) || !Translator.IsTextJapanese(text)) return text;

        if (conciergeDict.TryGetValue(text, out var known) && !string.IsNullOrEmpty(known)) return known;
        if (npcDict.TryGetValue(text, out var npcKnown) && !string.IsNullOrEmpty(npcKnown)) return npcKnown;
        if (playerDict.TryGetValue(text, out var playerKnown) && !string.IsNullOrEmpty(playerKnown)) return playerKnown;
        if (text.Length <= MaxNameLength) return romanizer.ToRomaji(text);

        return text;
    }
}
