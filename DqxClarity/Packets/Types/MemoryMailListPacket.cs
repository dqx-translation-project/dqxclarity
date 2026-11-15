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
// The parse is strict: the count must be sane and the last body must end
// exactly at the end of the packet, otherwise PacketLayoutException makes
// PacketGuard pass the original through and file a mismatch report. Only
// fields that are actually translated are rewritten; everything else is
// copied byte-for-byte. A sender name that wouldn't fit the client's name
// buffer is left in Japanese (MailSenderNamePacket.FitsNameBuffer), same as
// the other mail packets.
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
    private const int MaxRecords = 64;
    private const int MaxTextBytes = 4096;

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
        var reader = new PacketReader(_raw);
        reader.ReadBytesStrict(GlobalHeaderPrefixBytes, "memory mail header");
        var count = reader.ReadCountStrict("memory mail count", MaxRecords);

        var records = new List<((int Start, int Length, string Text) Name, (int Start, int Length, string Text) Body)>();
        for (var i = 0; i < count; i++)
        {
            reader.ReadBytesStrict(RecordHeaderBytes, $"record {i + 1} header");
            var nameStart = reader.Position;
            var name = reader.ReadCStringStrict($"record {i + 1} name", MaxTextBytes);
            var nameLen = reader.Position - 1 - nameStart;
            var bodyStart = reader.Position;
            var body = reader.ReadCStringStrict($"record {i + 1} body", MaxTextBytes);
            records.Add(((nameStart, nameLen, name), (bodyStart, reader.Position - 1 - bodyStart, body)));
        }
        reader.ExpectEnd("memory mail list");

        var conciergeDict = _deps.M00Dict("custom_concierge_mail_names");
        var npcDict = _deps.NpcNameDict();
        var playerDict = _deps.M00Dict("local_player_names");
        var mailDict = _deps.M00Dict("custom_mail");

        var patch = new PacketPatch(_raw);
        foreach (var (name, body) in records)
        {
            var newName = ResolveMailName(name.Text, conciergeDict, npcDict, playerDict, _deps.Romanizer);
            if (newName != name.Text && MailSenderNamePacket.FitsNameBuffer(name.Text, newName))
                patch.ReplaceText(name.Start, name.Length, newName);

            if (mailDict.TryGetValue(body.Text, out var en) && !string.IsNullOrEmpty(en) && en != body.Text)
                patch.ReplaceText(body.Start, body.Length, en);
        }

        if (patch.HasEdits) ModifiedData = patch.Build();
    }

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
