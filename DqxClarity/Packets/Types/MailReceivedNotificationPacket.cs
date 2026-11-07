using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The "you've got mail" popup notification -- opcode 0x97, marker 0xcc51.
// Different marker from both MailSenderNamePacket (0x732b, the mailbox list)
// and MailMessagePacket (0x2352, an opened letter) -- this is the transient
// toast shown the moment a letter arrives.
//
// Layout (after opcode + marker), confirmed identical across all three
// captures down to the byte:
//   prefix      15 bytes (passthrough -- counters/reserved, not decoded)
//   sender_id   u32 -- 0 for a system/organization sender (e.g. the
//               concierge/innkeepers' association, or the traveler's bazaar
//               merchant), a real (nonzero) id for a fellow player's
//               letter. This is the field that tells the two cases apart;
//               see below.
//   len_field   u16 -- meaning unconfirmed. Happened to equal the sender
//               name's byte length in the FIRST override capture (18,
//               matching "世界宿屋協会"'s 18 utf-8 bytes), which looked
//               promising, but the second override capture broke that
//               theory outright: len_field is 1 there while the name
//               ("旅人バザー") is a real 15 utf-8 bytes, and the player
//               capture had it at 0 against a real 9-byte name. Three
//               captures, three unrelated values against three different
//               name lengths -- conclusively not a length prefix, or
//               anything else this code needs to understand. Parsing still
//               relies solely on the null terminator, same as every other
//               text field in this codebase -- this field is pure
//               passthrough, left exactly as found.
//   sender_name cstring (utf-8, null-terminated) -- last field, nothing
//               trails it in either capture, so this packet is free to
//               grow/shrink like MailSenderNamePacket/MailMessagePacket
//               rather than needing HouseSignpostPacket's fixed-width-slot
//               treatment.
//
// sender_name is resolved one of two ways depending on sender_id:
//   sender_id == 0   Same "organization/department" case MailSenderNamePacket
//                     already handles -- m00 'custom_concierge_mail_names'
//                     first (e.g. "世界宿屋協会" -> "World Innkeepers"), then
//                     the npcs + custom_npc_name_overrides table. No romaji
//                     fallback on a miss, deliberately: an unrecognized
//                     override name is left in Japanese rather than
//                     transliterated, matching the sibling packet's rule.
//   sender_id != 0    A real player's letter -- normal player-name logic:
//                     m00 'local_player_names' override dict first, romaji
//                     fallback on miss.
//
// Samples: docs/packets/references/mail_received_notification
//          (sender_id 0, sender: 世界宿屋協会 -- the override case)
//          docs/packets/references/mail_received_notification_2
//          (sender_id 0x1ce07db2, sender: アーク -- the player case)
//          docs/packets/references/mail_received_notification_3
//          (sender_id 0, sender: 旅人バザー -- a second override case, with
//          a different sender and a different len_field value, confirming
//          the prefix/sender_id/len_field layout holds beyond the first
//          two captures)
public sealed class MailReceivedNotificationPacket : IPacket
{
    private const int PrefixBytes = 15;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MailReceivedNotificationPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        if (_raw.Length < PrefixBytes + 4 + 2) return;

        var reader = new PacketReader(_raw);
        var prefix = reader.ReadBytes(PrefixBytes).ToArray();
        var senderId = reader.ReadU32();
        var lenField = reader.ReadU16();
        var senderName = reader.ReadCString();
        var tail = reader.RemainingBytes().ToArray();

        if (!Translator.IsTextJapanese(senderName)) return;

        string? resolved;
        if (senderId != 0)
        {
            // A fellow player's letter -- normal player-name logic.
            var playerDict = _deps.M00Dict("local_player_names");
            resolved = playerDict.TryGetValue(senderName, out var known) && !string.IsNullOrEmpty(known)
                ? known
                : _deps.Romanizer.ToRomaji(senderName);
        }
        else
        {
            // System/organization sender -- same two dictionaries and same
            // exact-match-or-leave-alone rule as MailSenderNamePacket.
            var conciergeDict = _deps.M00Dict("custom_concierge_mail_names");
            var npcDict = _deps.NpcNameDict();
            resolved = conciergeDict.TryGetValue(senderName, out var c) && !string.IsNullOrEmpty(c) ? c
                : npcDict.TryGetValue(senderName, out var n) && !string.IsNullOrEmpty(n) ? n
                : null;
        }

        if (resolved == null || resolved == senderName) return;

        var writer = new PacketWriter();
        writer.WriteBytes(prefix);
        writer.WriteU32(senderId);
        writer.WriteU16(lenField);
        writer.WriteCString(resolved);
        writer.WriteBytes(tail);
        ModifiedData = writer.Build();
    }
}
