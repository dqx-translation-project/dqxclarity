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
// Sender names are resolved against two dictionaries: m00
// 'custom_concierge_mail_names' first (organizations/departments that send
// mail but aren't really NPCs — e.g. "開発チーム" -> "Dev. Team",
// "世界宿屋協会" -> "World Innkeepers", neither of which is in the base
// npcs dict), then npcs + custom_npc_name_overrides for ordinary NPC
// senders (e.g. "ムーロン"). A candidate string that doesn't exactly match
// either dictionary is left completely untouched — no romaji fallback here,
// deliberately, since a miss is just as likely to be a body-preview
// sentence (long, freeform Japanese prose) as an unrecognized sender name,
// and romaji-ing an arbitrary preview snippet would be worse than leaving
// it in Japanese. Every non-matching segment — including all the binary
// id/counter fields between entries — is written back byte-for-byte from
// the original payload, so this can't corrupt anything it doesn't
// specifically recognize as a known name.
//
// Samples: docs/packets/references/mailbox_letter,
//          docs/packets/references/mailbox_letter_2 — both captures
//          already contain all four sender occurrences (two for "ムーロン",
//          one each for "開発チーム" and "世界宿屋協会"), confirmed via the
//          same split-on-null approach this class now uses. Kept as
//          reference for the header/tick-field bytes; no longer treated as
//          ground truth for a fixed record layout.
public sealed class MailSenderNamePacket : IPacket
{
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

        var changed = false;
        var writer = new PacketWriter();
        foreach (var (bytes, hadTerminator) in segments)
        {
            if (TryResolve(bytes, conciergeDict, npcDict, out var newBytes))
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

    // Only ever returns true for an EXACT match against a known sender-name
    // dictionary. Binary segments (most of them) fail UTF-8 decode or
    // simply don't match any key and pass straight through unchanged; a
    // long body-preview sentence is valid Japanese but won't be a dict key
    // either, so it also passes through untouched.
    private static bool TryResolve(
        byte[] segment,
        Dictionary<string, string> conciergeDict,
        Dictionary<string, string> npcDict,
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

        if (resolved == null || resolved == text) return false;

        newBytes = Encoding.UTF8.GetBytes(resolved);
        return true;
    }
}
