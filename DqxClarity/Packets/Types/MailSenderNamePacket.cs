using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The mailbox list packet — carries a preview entry per letter currently in
// your mailbox (sender name, and for at least the first entry a truncated
// body-preview snippet). This is NOT one letter's sender duplicated: an
// earlier version of this class assumed a fixed shape of exactly two
// occurrences of one name with a body snippet in between, which only
// handled the first letter in the list and silently dropped every other
// sender further along (they landed inside what was, incorrectly, treated
// as opaque trailing "remainder"). Real mailboxes can hold an arbitrary
// number of letters, and the per-entry record shape isn't confirmed
// (whether every entry gets a preview snippet, how the id/counter fields
// between entries are sized, etc.) — so rather than guess at record
// boundaries again from too few captures, this scans the whole payload for
// null-terminated cstrings and rewrites only the ones that exactly match a
// known sender name.
//
// Sender names are resolved against three dictionaries, in order: m00
// 'custom_concierge_mail_names' (organizations/departments that send mail
// but aren't really NPCs — e.g. "開発チーム" -> "Dev. Team", "世界宿屋協会"
// -> "World Innkeepers", neither of which is in the base npcs dict), then
// npcs + custom_npc_name_overrides for ordinary NPC senders (e.g.
// "ムーロン"), then 'local_player_names' for a fellow player's letter (a
// mailbox can absolutely contain player-sent mail, not just system/NPC
// senders — see MailReceivedNotificationPacket, which hits this same
// distinction via an explicit sender-id field). All three of those are
// exact-match dictionary lookups, so a long body-preview sentence still
// can't accidentally hit one — it just won't be a key in any of them.
//
// A player-name dictionary miss falls back to Romanizer.ToRomaji, same as
// every other player-name field in this codebase — but ONLY when the
// segment is short enough to plausibly BE a name (<= MaxNameLength utf-16
// chars, matching Romanizer.ToRomaji's own default cap and its "covers
// ~all dqx player names" rationale). That gate is deliberate: unlike the
// three dictionary lookups above, ToRomaji doesn't require a match — it'll
// transform ANY Japanese text it's given — and this packet also contains
// long, freeform body-preview prose (confirmed up to 24+ characters even
// truncated, in docs/packets/references/mailbox_letter) that must never
// be fed through it, or it comes back a mangled partial transliteration
// instead of the original Japanese. Real sender names in the samples on
// file top out at 6 characters, so MaxNameLength leaves generous headroom
// without going anywhere near preview-sentence territory.
//
// Every segment that doesn't resolve — including all the binary
// id/counter fields between entries and any body-preview text — is written
// back byte-for-byte from the original payload, so this can't corrupt
// anything it doesn't specifically recognize as a name.
//
// Samples: docs/packets/references/mailbox_letter,
//          docs/packets/references/mailbox_letter_2 — both captures
//          already contain all four sender occurrences (two for "ムーロン",
//          one each for "開発チーム" and "世界宿屋協会"), confirmed via the
//          same split-on-null approach this class now uses. Kept as
//          reference for the header/tick-field bytes; no longer treated as
//          ground truth for a fixed record layout.
//
//          docs/packets/references/mailbox_letter_3 — a four-letter mailbox
//          (three from "世界宿屋協会", one from a real player, "アーク")
//          that confirms the player-name branch against actual data instead
//          of just mirroring MailReceivedNotificationPacket's. Also the
//          first capture with an already-english body-preview snippet
//          ("You are right where you need to be.") sitting right next to
//          the untranslated "世界宿屋協会" sender segments -- IsTextJapanese
//          correctly skips it (no hiragana/katakana/kanji in it), so it's
//          further, real-world proof the split-on-null approach can't
//          confuse a preview sentence for a sender name regardless of
//          which language it happens to already be in.
public sealed class MailSenderNamePacket : IPacket
{
    // See the class doc comment: gates the romaji fallback so it only ever
    // fires on name-shaped segments, never on freeform body-preview prose.
    private const int MaxNameLength = 10;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MailSenderNamePacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        // Split on null terminators. Every text field seen in this packet
        // family is a null-terminated cstring, so this can't split a
        // multi-byte utf-8 sequence in half — it only ever lands on real
        // field boundaries, whatever the surrounding binary layout is.
        var segments = new List<(byte[] Bytes, bool HadTerminator)>();
        var start = 0;
        for (var i = 0; i < _raw.Length; i++)
        {
            if (_raw[i] != 0) continue;
            segments.Add((_raw[start..i], true));
            start = i + 1;
        }
        if (start < _raw.Length) segments.Add((_raw[start..], false));

        var conciergeDict = _deps.M00Dict("custom_concierge_mail_names");
        var npcDict = _deps.NpcNameDict();
        var playerDict = _deps.M00Dict("local_player_names");

        var changed = false;
        var writer = new PacketWriter();
        foreach (var (bytes, hadTerminator) in segments)
        {
            if (TryResolve(bytes, conciergeDict, npcDict, playerDict, _deps.Romanizer, out var newBytes))
            {
                changed = true;
                writer.WriteBytes(newBytes!);
            }
            else
            {
                writer.WriteBytes(bytes);
            }
            if (hadTerminator) writer.WriteU8(0);
        }

        if (!changed) return;
        ModifiedData = writer.Build();
    }

    // Binary segments (most of them) fail UTF-8 decode or simply don't
    // match anything and pass straight through unchanged. A long
    // body-preview sentence is valid Japanese and could in principle be
    // long enough to skip the romaji gate below, but it still won't be a
    // key in any of the three dictionaries, so the only way it's ever
    // rewritten is the length-gated romaji fallback — which is exactly why
    // that gate exists.
    private static bool TryResolve(
        byte[] segment,
        Dictionary<string, string> conciergeDict,
        Dictionary<string, string> npcDict,
        Dictionary<string, string> playerDict,
        IRomanizer romanizer,
        out byte[]? newBytes)
    {
        newBytes = null;
        if (segment.Length == 0) return false;

        string text;
        try { text = Encoding.UTF8.GetString(segment); }
        catch { return false; }

        if (!Translator.IsTextJapanese(text)) return false;

        string? resolved = null;
        if (conciergeDict.TryGetValue(text, out var known) && !string.IsNullOrEmpty(known))
            resolved = known;
        else if (npcDict.TryGetValue(text, out var npcKnown) && !string.IsNullOrEmpty(npcKnown))
            resolved = npcKnown;
        else if (playerDict.TryGetValue(text, out var playerKnown) && !string.IsNullOrEmpty(playerKnown))
            resolved = playerKnown;
        else if (text.Length <= MaxNameLength)
            resolved = romanizer.ToRomaji(text);

        if (resolved == null || resolved == text) return false;

        newBytes = Encoding.UTF8.GetBytes(resolved);
        return true;
    }
}
