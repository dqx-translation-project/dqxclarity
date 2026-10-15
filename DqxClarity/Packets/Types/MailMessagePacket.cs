using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;
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
// sender_name is resolved the same way MailSenderNamePacket resolves the
// same sender in the mailbox LIST, so a letter's sender always reads the
// same in both views -- three dictionaries in order: m00
// 'custom_concierge_mail_names' (organizations/departments that send mail
// but aren't ordinary NPCs, e.g. "開発チーム"/"世界宿屋協会"), then the
// npcs + custom_npc_name_overrides table for ordinary NPC senders, then
// 'local_player_names' for a fellow player's letter, with a romaji
// fallback on a player-name miss (Romanizer.ToRomaji's own length cap
// applies -- sender_name is a single bounded cstring here, so there's no
// body-prose-gets-romanized risk like the mailbox list has to guard
// against).
//
// This used to stop after the first two lookups with no player-name path
// at all, so a letter from a real player (confirmed via a live capture
// from "かし", an English body -- see mail_message_3) left the sender in
// Japanese while the mailbox list, which DID have the player-name branch,
// already showed it translated. Nothing in the header cleanly distinguishes
// a player sender from an NPC/org one (Data[8] differs -- 0x09 in both NPC
// samples, 0x01B3 in the player sample -- but that's one player capture,
// not enough to trust as a flag), so like MailSenderNamePacket this just
// walks the dictionary chain and lets the romaji fallback catch whatever's
// left. Trade-off, same as the list packet: an NPC/org sender missing from
// every dictionary now gets romanized rather than left in Japanese.
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
// TEMPLATES: some letters are the same every time except for a player's name
// and a number (the Travel Concierge's Tombola good-luck gift, for one), so
// there is no single fixed japanese body to key on. For those, a 'custom_mail'
// entry can be written as a template -- a japanese key containing the tokens
// <japanesename> and/or <number>, and an english value that uses
// <englishname> and/or <number>:
//   key:    <japanesename>さまが　ふくびきで\n幸運を　つかまれましたので\n幸運のおすそ分けとして\n旅のコンシェルジュから\nスペシャルふくびき券　<number>枚を\nお届けいたします。
//   value:  Since <englishname> struck it lucky\nplaying the Tombola, the Travel Concierge sends you <number> SP Tombola Ticket(s)\nto share in their good fortune!
// (No \n is needed between "Concierge" and "sends" -- the client wraps at 41
// characters on its own, but the words still need a space between them.) A
// body is tried as an exact 'custom_mail' key first, exactly as before; only
// when there is no exact hit are the template entries tried (any key that
// contains one of the two japanese-side tokens). A template matches when its
// literal text matches the body exactly with the name/number in place of the
// tokens; <number> accepts full-width digits (５) and is written back as
// ordinary digits. The matched name is resolved by 'local_player_names' first
// and a romaji fallback second -- the same player-name rule used everywhere
// else, and NOT the sender rules above (concierge/NPC tables), since this is a
// player named inside the letter, not the sender. If a template key uses a
// token more than once, every occurrence must be the same text.
//
// Samples: docs/packets/references/mail_message,
//          docs/packets/references/mail_message_2 (different sender, body,
//          and tail bytes; both agree the sender name starts at Data
//          offset 51),
//          docs/packets/references/mail_message_3 (player sender "かし",
//          already-English body -- the sender name still starts at Data
//          offset 51 and the body/tail shape is unchanged)
public sealed class MailMessagePacket : IPacket
{
    private const int HeaderBytes = 51;

    // Tokens for 'custom_mail' template entries (see the TEMPLATES note above).
    private const string JaNameToken = "<japanesename>";
    private const string EnNameToken = "<englishname>";
    private const string NumberToken = "<number>";

    // Compiled regexes for template keys, so a key is only built once.
    private static readonly ConcurrentDictionary<string, Regex> TemplateRegexes = new();

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
        string? newBody = null;
        var bodyChanged = false;
        if (mailDict.TryGetValue(_body, out var exact) && !string.IsNullOrEmpty(exact) && exact != _body)
        {
            newBody = exact;
            bodyChanged = true;
        }
        else if (TryTemplate(mailDict, _body) is { } templated && templated != _body)
        {
            newBody = templated;
            bodyChanged = true;
        }

        var nameChanged = newName != _senderName;
        if (!nameChanged && !bodyChanged) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(nameChanged ? newName : _senderName);
        writer.WriteCString(bodyChanged ? newBody! : _body);
        writer.WriteBytes(_tail);

        ModifiedData = writer.Build();
    }

    // Tries every 'custom_mail' entry that is a template (its japanese key
    // contains <japanesename> and/or <number>) against `body`. Returns the
    // filled-in english text for the first one that matches, or null.
    private string? TryTemplate(Dictionary<string, string> mailDict, string body)
    {
        foreach (var kv in mailDict)
        {
            var key = kv.Key;
            if (!key.Contains(JaNameToken, StringComparison.Ordinal) &&
                !key.Contains(NumberToken, StringComparison.Ordinal)) continue;
            if (string.IsNullOrEmpty(kv.Value)) continue;

            var match = TemplateRegexes.GetOrAdd(key, BuildTemplateRegex).Match(body);
            if (!match.Success) continue;

            var result = kv.Value;
            if (match.Groups["name"].Success)
                result = result.Replace(EnNameToken, ResolvePlayerName(match.Groups["name"].Value), StringComparison.Ordinal);
            if (match.Groups["number"].Success)
            {
                // full-width digits (５) -> ordinary digits
                var digits = match.Groups["number"].Value.Normalize(NormalizationForm.FormKC);
                result = result.Replace(NumberToken, digits, StringComparison.Ordinal);
            }
            return result;
        }
        return null;
    }

    // Turns a template key into an anchored regex: literal text is matched
    // exactly, <japanesename> becomes a one-line capture, and <number>
    // becomes a run of ordinary or full-width digits. A token that appears a
    // second time must repeat the first occurrence's text.
    private static Regex BuildTemplateRegex(string key)
    {
        var sb = new StringBuilder("^");
        var seenName = false;
        var seenNumber = false;
        var i = 0;
        while (i < key.Length)
        {
            if (string.CompareOrdinal(key, i, JaNameToken, 0, JaNameToken.Length) == 0)
            {
                sb.Append(seenName ? @"\k<name>" : "(?<name>.+?)");
                seenName = true;
                i += JaNameToken.Length;
            }
            else if (string.CompareOrdinal(key, i, NumberToken, 0, NumberToken.Length) == 0)
            {
                sb.Append(seenNumber ? @"\k<number>" : "(?<number>[0-9０-９]+)");
                seenNumber = true;
                i += NumberToken.Length;
            }
            else
            {
                sb.Append(Regex.Escape(key[i].ToString()));
                i++;
            }
        }
        sb.Append(@"\z");
        return new Regex(sb.ToString(), RegexOptions.CultureInvariant);
    }

    // A player named inside a letter's body (as opposed to its sender):
    // 'local_player_names' override first, romaji fallback second.
    private string ResolvePlayerName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        var playerDict = _deps.M00Dict("local_player_names");
        if (playerDict.TryGetValue(japanese, out var player) && !string.IsNullOrEmpty(player)) return player;
        return _deps.Romanizer.ToRomaji(japanese);
    }

    private string ResolveName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        var orgDict = _deps.M00Dict("custom_concierge_mail_names");
        if (orgDict.TryGetValue(japanese, out var org) && !string.IsNullOrEmpty(org)) return org;

        var npcDict = _deps.NpcNameDict();
        if (npcDict.TryGetValue(japanese, out var npc) && !string.IsNullOrEmpty(npc)) return npc;

        var playerDict = _deps.M00Dict("local_player_names");
        if (playerDict.TryGetValue(japanese, out var player) && !string.IsNullOrEmpty(player)) return player;

        return _deps.Romanizer.ToRomaji(japanese);
    }
}
