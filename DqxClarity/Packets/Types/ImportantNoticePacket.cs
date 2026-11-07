using System.Text;
using System.Text.RegularExpressions;

namespace DqxClarity.Packets.Types;

// The server-wide announcement banner (streaming rules, maintenance
// windows, etc). Was already recognised by name in DataPacketRouter's
// GetPacketName and already allowlisted natively (0x876185 was already in
// PacketWarden.cpp's KNOWN_PACKETS[]) but had no dispatcher entry, so it
// was never actually intercepted/translated -- this adds that.
//
// Layout (after opcode + marker):
//   header    8 bytes (passthrough, all zero in the one capture on file)
//   message   cstring (utf-8, null-terminated) -- ONE string that can
//             contain a literal ASCII "<PAGE>" marker mid-string when
//             there's a second page of content (e.g. maintenance info
//             appended to the usual streaming-rules notice). Not two
//             separate cstrings -- "<PAGE>" is just inline text within
//             the single message.
//   tail      7 bytes (passthrough -- "00 00 D9 55 12 3F 00" in the one
//             capture on file. Tried treating it as a crc32 of the message
//             in several encodings/substrings and none matched, so unlike
//             NpcDialoguePacket's crc_value this doesn't look like a
//             message-derived checksum -- left untouched. Flagging this as
//             genuinely unverified rather than confirmed-safe: if the
//             notice renders wrong after translation, this field is the
//             first thing to re-examine.)
//
// Unlike the roster/notification family (TeamJoinMessagePacket,
// PartyInvitationPacket, etc.) this is a real free-text announcement box,
// same category as NpcDialoguePacket/MailMessagePacket/CornerTextPacket --
// there's no adjacent per-record binary blob for a translated message to
// collide with, so this does NOT use the fixed-width-slot fix. The message
// is free to grow or shrink; GamePacket's outer wire-frame resize handles
// it, same as those confirmed-working packets.
//
// Two independent, narrowly-scoped replacements, each opt-in via an exact
// or trigger-phrase match -- anything that doesn't match passes through as
// the original Japanese untouched, same "don't touch what we don't have a
// real answer for" policy as every curated-text packet in this codebase:
//
//   1. Streaming-rules notice (first page, i.e. the text before "<PAGE>"
//      if present, or the whole message if not): EXACT match (after
//      trimming trailing newlines) against the known Japanese text from
//      the sample capture. On match, replaced wholesale with a fixed
//      custom English message -- this notice doesn't carry any variable
//      data, so there's nothing to preserve from the original.
//
//   2. Maintenance notice (second page, only reachable when "<PAGE>" is
//      present): only replaced if it contains "全サーバーのメンテナンス"
//      (all-servers maintenance) -- other kinds of second-page content
//      (unknown, never seen) are deliberately left alone. When it matches,
//      the date/time is extracted with a regex anchored on the actual
//      japanese markers (年/月/日, then the first two "H:MM" times) rather
//      than by raw numeric position, and used to fill a custom English
//      template. Note: this is a POSITION-INDEPENDENT extraction on
//      purpose -- the sample capture's numbers read year(2026)/month(8)/
//      day(13), not year/day/month as originally assumed going in, and
//      anchoring on the kanji rather than ordinal position sidesteps that
//      ambiguity entirely, however the server ever orders them.
//
// Sample: docs/packets/references/important_notice
public sealed class ImportantNoticePacket : IPacket
{
    private const int HeaderBytes = 8;
    private const string PageMarker = "<PAGE>";

    private const string StreamingNoticeJapanese =
        "動画配信はサーバー１０・１８・１９・２１・２２の\n" +
        "いずれかで「いまどんな？設定」を「配信中」にし\n" +
        "配信IDが判別可能な状態で表示し続けてください。\n" +
        "併せてガイドラインの確認もお願いします。\n" +
        "https://sqex.to/iDo";

    private const string StreamingNoticeReplacement =
        "Streaming is allowed on servers 10/18/19/21/22\n" +
        "only. Display your Streamer ID by setting your\n" +
        "\"Status Icon\" to \"Streaming\", and keep it visible\n" +
        "at all times while streaming the game.\n" +
        "More information here: https://sqex.to/iDo";

    private const string MaintenanceTriggerPhrase = "全サーバーのメンテナンス";

    // Anchored on the kanji/colon markers rather than raw ordinal position
    // -- see the class doc comment for why.
    private static readonly Regex MaintenanceDateTimeRegex = new(
        @"(\d+)年(\d+)月(\d+)日.*?(\d{1,2}):(\d{2}).*?(\d{1,2}):(\d{2})",
        RegexOptions.Singleline);

    private readonly byte[] _raw;

    private byte[] _header = Array.Empty<byte>();
    private string _message = "";
    private byte[] _tail = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public ImportantNoticePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes) return;
        var reader = new PacketReader(_raw);
        _header  = reader.ReadBytes(HeaderBytes).ToArray();
        _message = reader.ReadCString();
        _tail    = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var pageIdx = _message.IndexOf(PageMarker, StringComparison.Ordinal);
        var hasPage2 = pageIdx >= 0;
        var page1 = hasPage2 ? _message[..pageIdx] : _message;
        var page2 = hasPage2 ? _message[(pageIdx + PageMarker.Length)..] : null;

        var newPage1 = TryReplaceStreamingNotice(page1, out var page1Changed);
        var page2Changed = false;
        var newPage2 = page2;
        if (hasPage2)
            newPage2 = TryReplaceMaintenanceNotice(page2!, out page2Changed);

        if (!page1Changed && !page2Changed) return;

        var rebuilt = hasPage2 ? newPage1 + PageMarker + newPage2 : newPage1;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(rebuilt);
        writer.WriteBytes(_tail);
        ModifiedData = writer.Build();
    }

    private static string TryReplaceStreamingNotice(string page, out bool changed)
    {
        changed = false;
        var trimmed = page.TrimEnd('\n');
        if (trimmed != StreamingNoticeJapanese) return page;

        changed = true;
        var trailingNewlines = page[trimmed.Length..]; // preserve whatever separator followed
        return StreamingNoticeReplacement + trailingNewlines;
    }

    private static string TryReplaceMaintenanceNotice(string page, out bool changed)
    {
        changed = false;
        if (!page.Contains(MaintenanceTriggerPhrase, StringComparison.Ordinal)) return page;

        var match = MaintenanceDateTimeRegex.Match(page);
        if (!match.Success) return page; // trigger phrase present but couldn't parse the date/time -- leave untouched

        var year = match.Groups[1].Value;
        var month = match.Groups[2].Value;
        var day = match.Groups[3].Value;
        var startHour = match.Groups[4].Value;
        var startMinute = match.Groups[5].Value;
        var endHour = match.Groups[6].Value;
        var endMinute = match.Groups[7].Value;

        changed = true;
        var leadingNewlines = page[..(page.Length - page.TrimStart('\n').Length)]; // preserve whatever separator preceded
        var replacement =
            "{color=yellow}Maintenance Announcement{reset}\n" +
            "All servers will be undergoing maintenance on\n" +
            $"{month}/{day}/{year} from {startHour}:{startMinute} JST to {endHour}:{endMinute} JST.";
        return leadingNewlines + replacement;
    }
}
