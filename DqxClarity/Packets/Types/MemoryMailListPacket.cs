using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// Memory Mail list -- opcode 0x97, marker 0xedec. Mail previously sent by
// NPCs that the player can still browse after deleting it from their
// normal inbox -- a separate "memory" archive, paginated 10 entries per
// page (both captures: exactly 10 records, matching the u32 count field
// at the end of the global header; the second capture's leading byte and
// the "01"/"02" byte a few bytes later both look like page-number fields,
// consistent with paging through more than 10 total letters).
//
// Unlike MailInboxViewPacket (opcode 0x79/0x2b15, the fixed-3-slot mail
// screen this reuses translation logic from), this one is a genuinely
// variable-length, count-prefixed repeating list -- confirmed by
// round-tripping BOTH captures byte-for-byte in a from-scratch parser
// before writing this class: the two captures are 996 and 1004 bytes of
// Data respectively despite both holding exactly 10 records, so record
// content freely varies the packet's total length (same "growable" family
// as MailSenderNamePacket/MailMessagePacket, not HouseSignpostPacket/
// MailInboxViewPacket's fixed-width-slot family).
//
// Layout (after opcode + marker):
//   global_header   26 bytes -- mostly passthrough/opaque, except the
//                   last 4 bytes, a u32 entry count (confirmed 10 in both
//                   captures, matching the actual record count found by
//                   parsing all the way to the end of Data)
//   count x records, each:
//     record_header   12 bytes (passthrough -- a 4-byte type/flag [04 in
//                     every record but one across both captures, 01
//                     once], a 4-byte value that decreases monotonically
//                     record to record [almost certainly a timestamp], a
//                     2-byte id, and 2 zero-bytes)
//     name            cstring (utf-8, null-terminated)
//     body            cstring (utf-8, null-terminated) -- a preview,
//                     truncated with "…" when too long (70-72 bytes in
//                     every record on file)
//
// No slot padding anywhere -- name/body/the next record's header sit back
// to back with nothing between them, confirmed by the byte-exact
// round-trip mentioned above.
//
// name and body are resolved with the same logic as MailInboxViewPacket's
// corresponding fields, per the user's request to reuse that packet's
// translation rules here:
//   name   m00 'custom_concierge_mail_names' first, then npcs +
//          custom_npc_name_overrides (every name seen so far -- ムーロン,
//          アンルシア, メリル, ミローレ, ムツキ, 聖天の使い, ナガツキ,
//          カササギ -- is an NPC, not a player), then 'local_player_names'
//          (tried anyway, same as MailInboxViewPacket/MailSenderNamePacket,
//          in case a player's own old sent-mail ever turns up here), then
//          Romanizer.ToRomaji as a last resort gated to <= MaxNameLength
//          characters so it can never fire on the body field sitting right
//          next to it.
//   body   m00 'custom_mail', verbatim match or left untouched -- same
//          dictionary and same rule MailMessagePacket/MailInboxViewPacket
//          use, NOT machine translated. A truncated preview can't
//          byte-for-byte match a dictionary keyed on the complete letter
//          text, so it naturally stays untouched without any special-case
//          truncation detection.
//
// There's no "reading"/furigana field here (that was specific to
// MailInboxViewPacket's fixed-slot layout) -- just name and body, so this
// class is correspondingly simpler.
//
// Samples: docs/packets/references/memory_mail (page 1, 10 entries: 2x
//          ムーロン, アンルシア, 2x メリル, 2x ミローレ, 2x ムツキ, 聖天
//          の使い)
//          docs/packets/references/memory_mail_2 (page 2, a different 10
//          entries -- 2x 聖天の使い, 2x ナガツキ, 2x ムーロン, 2x
//          カササギ, 2x メリル -- confirming the global-header/
//          record-header layout and count field against an entirely
//          different page)
public sealed class MemoryMailListPacket : IPacket
{
    private const int GlobalHeaderPrefixBytes = 22; // 26-byte global header minus the trailing u32 count
    private const int RecordHeaderBytes = 12;
    private const int MaxNameLength = 10;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MemoryMailListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < GlobalHeaderPrefixBytes + 4) return;

        var reader = new PacketReader(_raw);
        var headerPrefix = reader.ReadBytes(GlobalHeaderPrefixBytes).ToArray();
        var count = (int)reader.ReadU32();
        if (count < 0) return;

        var recordHeaders = new byte[count][];
        var names = new string[count];
        var bodies = new string[count];

        for (var i = 0; i < count; i++)
        {
            // This packet's record count and shape are only confirmed for
            // what's on file -- bail rather than guess at a malformed or
            // unexpectedly-shaped payload.
            if (reader.Remaining < RecordHeaderBytes) return;
            recordHeaders[i] = reader.ReadBytes(RecordHeaderBytes).ToArray();
            names[i] = reader.ReadCString();
            bodies[i] = reader.ReadCString();
        }

        var conciergeDict = _deps.M00Dict("custom_concierge_mail_names");
        var npcDict = _deps.NpcNameDict();
        var playerDict = _deps.M00Dict("local_player_names");
        var mailDict = _deps.M00Dict("custom_mail");

        var resolvedNames = new string[count];
        var resolvedBodies = new string[count];
        var changed = false;

        for (var i = 0; i < count; i++)
        {
            resolvedNames[i] = ResolveMailName(names[i], conciergeDict, npcDict, playerDict, _deps.Romanizer);

            // Verbatim dictionary lookup only -- see class doc comment. A
            // truncated preview just won't be a key in 'custom_mail', so
            // this naturally no-ops on the common case.
            resolvedBodies[i] = mailDict.TryGetValue(bodies[i], out var known) && !string.IsNullOrEmpty(known)
                ? known
                : bodies[i];

            if (resolvedNames[i] != names[i] || resolvedBodies[i] != bodies[i])
                changed = true;
        }

        if (!changed) return;

        var writer = new PacketWriter();
        writer.WriteBytes(headerPrefix);
        writer.WriteU32((uint)count);
        for (var i = 0; i < count; i++)
        {
            writer.WriteBytes(recordHeaders[i]);
            writer.WriteCString(resolvedNames[i]);
            writer.WriteCString(resolvedBodies[i]);
        }
        ModifiedData = writer.Build();
    }

    // Same three-dictionary-then-gated-romaji priority as
    // MailSenderNamePacket/MailInboxViewPacket.
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
