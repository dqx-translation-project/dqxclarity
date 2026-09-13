using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The mail-reading screen's 3-slot window -- opcode 0x79, marker 0x2b15.
// Different opcode/marker from every other mail packet (MailSenderNamePacket
// 0x97/0x732b, MailMessagePacket 0x97/0x2352, MailReceivedNotificationPacket
// 0x97/0xcc51) -- this is the view you land on when you open your mailbox,
// showing three letters (sender, a truncated body preview, and a kana
// reading of the sender) at fixed positions.
//
// Confirmed a FIXED-TOTAL-LENGTH packet: both captures on file are exactly
// 854 bytes of Data despite wildly different name/body/reading content and
// lengths in every one of the 6 (2 captures x 3 slots) records -- so, same
// as HouseSignpostPacket/AllianceMemberDetailPacket, every text field here
// lives in a reserved fixed-width slot (text + null terminator + zero-pad
// to the slot's full width), never a variable-length field. Layout, byte
// offsets confirmed identical in both captures:
//
//   global_header   20 bytes (Data[0..20), passthrough -- not decoded)
//   x3 records, each 278 bytes:
//     record_header   78 bytes (passthrough -- id/tick fields; a repeated
//                     4-byte value appears twice inside it in every record,
//                     both player and npc/org alike, so it reads as a mail
//                     id/timestamp rather than anything that tells the two
//                     cases apart -- unlike MailReceivedNotificationPacket,
//                     nothing here was needed as an explicit sender-type
//                     flag; see below for why)
//     name            20-byte fixed slot -- the sender's name
//     body            148-byte fixed slot -- a preview of the letter body,
//                     truncated with "…" if too long to fit (both captures'
//                     first two records hit exactly 72 bytes of text, right
//                     at the truncation limit; the third record in each
//                     capture is short enough to fit untruncated). See
//                     below for how it's resolved.
//     reading         32-byte fixed slot -- see below
//
// name is resolved with the exact same three-dictionary-then-gated-romaji
// logic as MailSenderNamePacket: m00 'custom_concierge_mail_names' first
// (organizations/departments -- none in either capture on file, but the
// pattern is the same feature), then npcs + custom_npc_name_overrides
// (e.g. "運営チーム", "三闘士", "ラダ・ガート"), then 'local_player_names'
// for an actual player's letter (e.g. "メハシェハ", "イッセイ"), and
// finally Romanizer.ToRomaji as a last resort -- but only when the name is
// short enough to plausibly BE a name (<= MaxNameLength chars, same gate
// and same rationale as MailSenderNamePacket: this packet also carries a
// long freeform body preview right next to the name, and romaji-ing that
// would mangle it). Every name in both captures is well under the gate (3
// to 6 characters), so this hasn't needed to reject a real sample yet.
//
// reading is a phonetic aid, not independently translatable: for an
// npc/org sender it's the all-hiragana pronunciation of the kanji/katakana
// name (e.g. "運営チーム" -> "うんえいちーむ", "ラダ・ガート" ->
// "らだがーと") -- a string with no dictionary entry of its own and no
// sane way to machine-translate without producing garbage, so it's left
// untouched. For a PLAYER sender, though, this slot is confirmed (both
// captures, both player records) to hold the exact same raw string as the
// name slot -- not a kana reading at all, just the name repeated verbatim.
// So the rule actually implemented: if reading's raw text exactly equals
// name's raw text, rewrite it to the same resolved value as name (it's
// unambiguously the same field, duplicated -- see HouseSignpostPacket's
// player-name slot for the identical "duplicate occurrence gets the same
// translation" precedent); otherwise (a genuine kana reading) leave it
// completely alone.
//
// body is looked up verbatim in m00 'custom_mail' -- the exact same
// dictionary and exact same "verbatim match or leave it alone" rule
// MailMessagePacket already uses for a letter's full text, NOT machine
// translated and NOT run through name-resolution logic. A truncated
// preview (ending in "…") is missing the tail of whatever the full,
// untruncated body is, so it can't be a byte-for-byte match against a
// dictionary keyed on the complete text -- it'll simply miss and stay
// as-is, which is exactly the desired "leave it alone" outcome and needs
// no special-casing to get right. Only an untruncated preview (short
// enough to fit the 148-byte slot in full, like record 2 in both captures
// on file) can actually hit a 'custom_mail' entry.
//
// Critically, this is why identifying every field here by fixed byte
// offset (rather than by content shape) matters: a short untruncated body
// preview (32-49 bytes, well within name-length territory) could easily
// be mistaken for a name field if this were guessed at from length alone
// -- but because body is always read from its own reserved slot, it's
// only ever run through the 'custom_mail' lookup, never through
// ResolveMailName, regardless of how short a particular letter's preview
// turns out to be.
//
// Samples: docs/packets/references/mail_inbox_view (record0: メハシェハ,
//          a player letter; record1: 運営チーム, an org letter; record2:
//          イッセイ, a second player letter -- whose body is an ENGLISH
//          "Happy birthday... Mr.Shobu sama!..." message, confirming
//          IsTextJapanese correctly no-ops on a body that isn't Japanese
//          at all, same as MailSenderNamePacket's mailbox_letter_3)
//          docs/packets/references/mail_inbox_view_2 (three npc/org
//          letters: 三闘士, ラダ・ガート, 運営チーム -- no player letter,
//          but confirms every fixed offset holds against three entirely
//          different senders/bodies/readings from capture 1)
public sealed class MailInboxViewPacket : IPacket
{
    private const int GlobalHeaderBytes = 20;
    private const int RecordCount = 3;
    private const int RecordHeaderBytes = 78;
    private const int NameSlotBytes = 20;
    private const int BodySlotBytes = 148;
    private const int ReadingSlotBytes = 32;
    private const int RecordStride = RecordHeaderBytes + NameSlotBytes + BodySlotBytes + ReadingSlotBytes; // 278
    private const int ExpectedTotalLength = GlobalHeaderBytes + RecordCount * RecordStride; // 854

    // Same gate and same rationale as MailSenderNamePacket.MaxNameLength:
    // keeps the romaji fallback from ever firing on something that isn't
    // actually name-shaped.
    private const int MaxNameLength = 10;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MailInboxViewPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        // This packet's shape has only ever been confirmed at exactly this
        // length. Bail rather than guess if a future capture turns out
        // differently sized (e.g. a mailbox with fewer than 3 letters).
        if (_raw.Length != ExpectedTotalLength) return;

        var reader = new PacketReader(_raw);
        var globalHeader = reader.ReadBytes(GlobalHeaderBytes).ToArray();

        var recordHeaders = new byte[RecordCount][];
        var names = new string[RecordCount];
        var bodies = new string[RecordCount];
        var readings = new string[RecordCount];

        for (var i = 0; i < RecordCount; i++)
        {
            recordHeaders[i] = reader.ReadBytes(RecordHeaderBytes).ToArray();
            names[i] = ReadSlotText(reader.ReadBytes(NameSlotBytes));
            bodies[i] = ReadSlotText(reader.ReadBytes(BodySlotBytes));
            readings[i] = ReadSlotText(reader.ReadBytes(ReadingSlotBytes));
        }

        var conciergeDict = _deps.M00Dict("custom_concierge_mail_names");
        var npcDict = _deps.NpcNameDict();
        var playerDict = _deps.M00Dict("local_player_names");
        var mailDict = _deps.M00Dict("custom_mail");

        var resolvedNames = new string[RecordCount];
        var resolvedBodies = new string[RecordCount];
        var resolvedReadings = new string[RecordCount];
        var changed = false;

        for (var i = 0; i < RecordCount; i++)
        {
            resolvedNames[i] = ResolveMailName(names[i], conciergeDict, npcDict, playerDict, _deps.Romanizer);

            // Verbatim dictionary lookup only -- see class doc comment. A
            // truncated preview just won't be a key in 'custom_mail', so
            // this naturally no-ops on the common case without needing to
            // detect truncation itself.
            resolvedBodies[i] = mailDict.TryGetValue(bodies[i], out var knownBody) && !string.IsNullOrEmpty(knownBody)
                ? knownBody
                : bodies[i];

            // See class doc comment: a reading slot that's a verbatim copy
            // of the name slot (the player-sender case) gets the same
            // resolved value; a genuine kana reading (the npc/org case) is
            // left alone since there's no sane way to translate it.
            resolvedReadings[i] = readings[i] == names[i] ? resolvedNames[i] : readings[i];

            if (resolvedNames[i] != names[i] || resolvedBodies[i] != bodies[i] || resolvedReadings[i] != readings[i])
                changed = true;
        }

        if (!changed) return;

        var writer = new PacketWriter();
        writer.WriteBytes(globalHeader);
        for (var i = 0; i < RecordCount; i++)
        {
            writer.WriteBytes(recordHeaders[i]);
            writer.WriteBytes(BuildSlot(resolvedNames[i], NameSlotBytes));
            writer.WriteBytes(BuildSlot(resolvedBodies[i], BodySlotBytes));
            writer.WriteBytes(BuildSlot(resolvedReadings[i], ReadingSlotBytes));
        }
        ModifiedData = writer.Build();
    }

    // Same three-dictionary-then-gated-romaji priority as
    // MailSenderNamePacket.TryResolve. Kept as its own copy here (rather
    // than shared) since this packet's caller works in strings/fixed slots
    // throughout, not raw byte segments.
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

    // Slots are null-terminated cstrings zero-padded out to a fixed width;
    // ReadCString can't be used directly since it would leave the reader
    // positioned right after the terminator instead of at the slot's fixed
    // end, so the slot is read as a raw fixed-size chunk and parsed locally.
    private static string ReadSlotText(ReadOnlySpan<byte> slot)
    {
        var nullIdx = slot.IndexOf((byte)0);
        var textBytes = nullIdx >= 0 ? slot[..nullIdx] : slot;
        return Encoding.UTF8.GetString(textBytes);
    }

    private static byte[] BuildSlot(string text, int slotWidth)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        if (bytes.Length > slotWidth - 1) bytes = bytes[..(slotWidth - 1)]; // leave room for the terminator
        var result = new byte[slotWidth]; // zero-initialized: terminator + padding for free
        Buffer.BlockCopy(bytes, 0, result, 0, bytes.Length);
        return result;
    }
}
