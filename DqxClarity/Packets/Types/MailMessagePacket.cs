using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The full letter contents shown when you open a piece of mail — sender
// name plus the message body. Different wire marker (0x2352) from
// MailSenderNamePacket's (0x732B), even though both share opcode 0x97 and
// the same "60 DF 1E 01"-shaped tick field at Data[16..20] — likely
// sibling packets within the mail feature rather than the same struct.
//
// Unlike MailSenderNamePacket (which only touches the sender name because
// that's all it was asked to do), this one also handles the body, since
// that's the actual point of a "mail message" packet.
//
// Layout (after opcode + marker):
//   header        51 bytes (passthrough — counters/ids, includes the tick
//                 field at [16..20]. Held byte-for-byte identical position
//                 for the sender-name field across two captures with very
//                 different bodies/tails, so 51 is solid.)
//   sender_name   cstring (utf-8, null-terminated, no length prefix)
//   body_text     cstring (the letter's message)
//   tail          4 bytes (passthrough — "C5 01 00 00" in one capture,
//                 "00 00 00 00" in the other; meaning not confirmed)
//
// sender_name is resolved against the full m00 'npcs' table plus
// 'custom_concierge_mail_names' (organizations/departments that send mail
// but aren't ordinary NPCs — same source MailSenderNamePacket uses for
// "開発チーム"/"世界宿屋協会"-style senders), NOT custom_npc_name_overrides.
// No romaji fallback on miss — an unresolved sender is left in the original
// japanese rather than transliterated, same "don't touch what we don't have
// a real answer for" handling as the body text below.
//
// body_text is looked up verbatim in m00 'custom_mail' — NOT machine
// translated. Letter bodies are pulled from a fixed, curated set (confirmed:
// the body text in docs/packets/references/mail_message is byte-for-byte
// entry #20 of custom_mail.json), so a dictionary miss should leave the
// text as-is rather than falling through to the NpcDialoguePacket-style
// bad-strings/cache/machine-translate pipeline. 'custom_mail' is ingested
// automatically by TranslationUpdater's generic /json/*.json -> m00_strings
// routing (file tag = filename without extension), same as
// 'custom_tower_answers' — no updater changes needed.
//
// Samples: docs/packets/references/mail_message,
//          docs/packets/references/mail_message_2 (different sender, body,
//          and tail bytes; both agree the sender name starts at Data
//          offset 51)
public sealed class MailMessagePacket : IPacket
{
    private const int HeaderBytes = 51;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _senderName = "";
    private string _body = "";
    private byte[] _tail = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public MailMessagePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes) return;
        var reader = new PacketReader(_raw);
        _header     = reader.ReadBytes(HeaderBytes).ToArray();
        _senderName = reader.ReadCString();
        _body       = reader.ReadCString();
        _tail       = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        var newName = ResolveName(_senderName);

        var mailDict = _deps.M00Dict("custom_mail");
        var bodyChanged = mailDict.TryGetValue(_body, out var newBody)
            && !string.IsNullOrEmpty(newBody) && newBody != _body;

        var nameChanged = newName != _senderName;
        if (!nameChanged && !bodyChanged) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(nameChanged ? newName : _senderName);
        writer.WriteCString(bodyChanged ? newBody! : _body);
        writer.WriteBytes(_tail);

        ModifiedData = writer.Build();
    }

    private string ResolveName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        var dict = _deps.M00Dict("npcs", "custom_concierge_mail_names");
        return dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known) ? known : japanese;
    }
}
