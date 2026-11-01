using System.Buffers.Binary;
using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// One packet wire-format with a type discriminator at offset 11. Type byte
// dictates two things: (1) what header_offset to use before the name field
// (NPC/Party/Fellow/PartyNpc=575, Monster/ScoutableMonster=402 — a game update
// inserted one byte somewhere in each kind's header, shifting these +1 from
// the original 574/401. Confirmed independently via captured packets for
// Player and Monster; Npc/Party/Fellow are inferred to share Player's shift
// since they use the same 574-origin offset, but haven't been captured
// post-update. Player has since moved AGAIN, to 605: a later update grew
// the two 60-byte equipment-display blocks in its header to 72 bytes each and
// added a few more bytes after them -- 30 bytes in all, see below), (2) how the
// name is resolved:
//   Player           — local_player_names m00 dict → romanizer fallback, \x04 prefix
//   Party            — local_player_names m00 dict, then custom_npc_name_overrides
//                      m00 dict, romanizer fallback on miss in both, \x04 prefix
//                      (a party member entity is still a player, so a name
//                      override set for that player elsewhere should apply here
//                      too, not just the romaji fallback; custom_npc_name_overrides
//                      is also checked, same two tiers in the same order as
//                      Fellow)
//   NPC              — npc name dict, pass-through on miss
//   Monster          — monsters m00 dict, pass-through on miss (no romanizer fallback)
//   ScoutableMonster — same as Monster (see type byte 0x24 below)
//   Fellow           — local_player_names m00 dict, then custom_npc_name_overrides
//                      m00 dict, romanizer fallback on miss in both, \x04 prefix
//                      (confirmed via a ガヴァ capture that stayed untranslated
//                      with no dict match, and a hired フェロー whose translated
//                      name rendered without the GM-face-icon prevention prefix)
//   PartyNpc         — custom_npc_name_overrides m00 dict, romanizer fallback on
//                      miss, \x04 prefix (type bytes 0x86, 0x87, 0x89, 0x8A,
//                      AND 0x8B; confirmed via six captures -- エステラ and
//                      ギルガラン on 0x87, ドルタム on 0x86, ユーライザ on
//                      0x89, アンルシア on 0x8A, ラダ・ガート on 0x8B -- all
//                      NPC companions occupying a party slot in NPC-party
//                      content, all sharing the identical 575-byte
//                      header/entity_length+cstring layout as Player/Npc/
//                      Party/Fellow, differing only in that discriminator
//                      byte. No confirmed behavioral difference between
//                      0x86/0x87/0x89/0x8A/0x8B has turned up, so all five
//                      are grouped under one EntityKind/resolution path here
//                      rather than kept as separate cases; split them apart
//                      later if a real difference surfaces. Unlike Fellow
//                      this has no player-name-dict tier: these are
//                      quest/event NPCs added directly to the party, not
//                      hired player characters, so there's no player name
//                      they could ever match)
//
// A mismatch report from another player (captured within 20 seconds of each
// other) had the name 4 bytes later in BOTH a Monster and a Player entity:
// Monster 402 -> 406, Player 609 -> 613, with the character id moving along
// with the name (394 -> 398, still 215 bytes before the length field). The
// cause is not known. It is not simply "being in combat" (the packet
// author's own client, and another tester who fought dozens of times, never
// saw it) and it is not a client update (that player's client version had not
// changed). Something on the server side or specific to that player/session is
// the remaining guess. (The extra bytes in the captures look like entity ids,
// which first suggested a combat list, but that did not hold up.) The id
// position is matched against the 609 capture, not confirmed -- that capture
// belongs to another player, so it could not be checked against a roster.
//
// Because the shift keeps changing (575 -> 605 -> 609 -> 613, 402 -> 406),
// the listed offsets are now only the first things tried: when none of them
// fits, the header is searched in 4-byte steps beyond each of them (see
// ScanForName). The old offsets stay first so a client that has not updated
// still parses exactly as before.
//
// Header offsets are a candidate LIST per kind, not a single number: each
// candidate is checked against the data (entity_length is 2..255, the name
// ends in a null exactly entity_length bytes later, and it is valid UTF-8
// with no control characters besides the \x04 prefix) and the first one that
// checks out is used. If none does the packet is left completely alone. That
// matters because a wrong offset used to be silent corruption rather than a
// miss: with Player still at 575 after the move to 605, the "name" read from
// 575 was an empty string, which was then "translated" to a bare \x04 and
// written in place of 5 zero bytes in the middle of the header, growing the
// packet by one byte and shifting everything after it. The Party and Fellow
// kinds share Player's character layout, so they also try 605 after 575 in
// case they moved along with it; PartyNpc/Npc try it too, purely as a safety
// net (their captures, the latest ones for アンルシア and ラダ・ガート,
// still sit at 575).
//
// Layout:
//   header_data           header_offset bytes
//   entity_length         u32  (utf-8 byte length of entity_name including null)
//   entity_name           cstring
//   remainder             rest of payload
//
// Sample: docs/packets/references/scoutable_monster (type byte 0x24,
//         previously logged as unhandled "Entity (0x24)" -- a monster on
//         the field that can be scouted to join your party, distinct from
//         the plain Monster kind (0x02) despite sharing its layout exactly)
//         docs/packets/references/entity_fellow_gava (type byte 0x85,
//         ガヴァ -- a hired fellow with no match in either Fellow dict,
//         exposing the missing romanizer fallback: it was passing through
//         untranslated instead of falling back to romaji like every other
//         entity kind with a dict-miss path does)
//         docs/packets/references/entity_party_npc_yuraiza (type byte 0x89,
//         ユーライザ -- previously logged as unhandled "Entity (0x89)";
//         decoded cleanly against the existing 575-byte PartyNpc layout with
//         no changes needed, confirming 0x89 is a third PartyNpc type byte
//         alongside 0x86/0x87)
//         docs/packets/references/entity_party_npc_rada_gart (type byte 0x8B,
//         ラダ・ガート -- previously logged as unhandled "Entity (0x8B)";
//         same story as 0x89, a fourth PartyNpc type byte with the identical
//         575-byte layout)
//         docs/packets/references/entity_party_npc_anrushia (type byte 0x8A,
//         アンルシア -- previously logged as unhandled "Entity (0x8A)"; same
//         story again, a fifth PartyNpc type byte with the identical
//         575-byte layout)
//
// A Player-kind entity also carries, at fixed Data offset 390 (inside the
// otherwise-opaque 575-byte header), a persistent u32 character id --
// confirmed to be the exact same id CharacterLogListPacket reports per
// roster slot, by capturing both packet types for the same known character
// (ショウブ, one week apart) and finding an identical, high-entropy value in
// both. That correlation is how PlayerContext identifies which character is
// currently logged in without a login hook -- see its doc comment. This
// class doesn't otherwise care about the id; it just reports it whenever a
// Player-kind entity comes through, including entities that turn out to
// belong to someone else's account entirely (PlayerContext silently ignores
// any id that isn't in its own roster).
//
// NAMEPLATE TOGGLES: the [launcher] "Nameplates" checkbox is split three
// ways (PacketDependencies.TranslatePlayerNameplates/NpcNameplates/
// MonsterNameplates) so a user can turn off translation for one entity
// category without affecting the others:
//   Player nameplates  -> gates EntityKind.Player only
//   NPC nameplates     -> gates EntityKind.Npc, Party, Fellow, AND PartyNpc
//                         (a party member is still rendered as a name-tagged
//                         character the same way an NPC is, and Fellow/
//                         PartyNpc are both the same kind of "non-monster
//                         companion" nameplate)
//   Monster nameplates -> gates EntityKind.Monster and ScoutableMonster
//
// These checks live ONLY in Build(), each as the very first line of its
// case, before any dict lookup -- Parse() above (including the
// PlayerContext.NotifyEntityId call) runs unconditionally regardless of any
// toggle. That separation is deliberate: turning off Player nameplates must
// not stop PlayerContext from identifying the logged-in character, since
// other packets (dialogue's <pnplacehold>/<snplacehold> substitution, for
// one) depend on that identification having happened even when the
// player's own nameplate text is left untranslated.
public sealed class EntityPacket : IPacket
{
    private const int TypeByteOffset = 11;
    private const int CharacterIdOffset = 390; // only meaningful for EntityKind.Player (575/605 layouts)
    // In the 605, 609 and 613 layouts the character id sits 215 bytes before the
    // name's length field (390 for 605, 394 for 609, 398 for 613): the extra
    // bytes of the later layouts come BEFORE the id, so the id moved with the
    // name.
    private const int CharacterIdBeforeName = 215;
    private const int MaxNameBytes = 255;       // entity_length sanity cap (incl. null)
    private const int ScanStepBytes = 4;        // the header grows in whole u32s
    private const int ScanMaxBytes = 64;        // how far past a listed offset to look

    // Candidate header offsets (Data offset of entity_length), tried in order.
    private static readonly int[] PlayerOffsets    = { 605, 609, 613, 575 };
    private static readonly int[] PartyOffsets     = { 575, 605, 609, 613 };
    private static readonly int[] CharacterOffsets = { 575, 605, 609, 613 };
    private static readonly int[] MonsterOffsets   = { 402, 406 };

    // Job abbreviations a player's nameplate shows instead of their name when
    // they hide it in auto-matched content (WAR = Warrior, PRI = Priest, ...).
    // They are English from the start, so there is nothing to translate and
    // the normal path would never mark them; without the \x04 prefix the
    // client treats an unprefixed ASCII name as a GM and shows the red name /
    // GM face. Matched exactly (upper case) against the whole name, for Player
    // and Party entities only, and written back unchanged apart from the prefix.
    private static readonly HashSet<string> ClassAbbreviations = new(StringComparer.Ordinal)
    {
        "WAR", "PRI", "MGE", "THF", "MRT", "MIN", "GLA", "PLD", "ARM", "RNG",
        "SGE", "STA", "MON", "ITM", "DNC", "FOR", "DRU", "GAD", "DTH", "DMN",
        "PIR", "GRD", "DGM", "HRM", "STK",
    };

    private enum EntityKind
    {
        None, Player, Monster, Npc, Party, Fellow, ScoutableMonster, PartyNpc,
    }

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private EntityKind _kind = EntityKind.None;
    private int[] _headerOffsets = Array.Empty<int>();
    private int _headerOffset;
    private byte[] _header = Array.Empty<byte>();
    private string _entityName = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public EntityPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;

        if (_raw.Length <= TypeByteOffset) return;
        var typeByte = _raw[TypeByteOffset];

        (_kind, _headerOffsets) = typeByte switch
        {
            // Player moved 575 -> 605 in a later update (confirmed via a
            // capture of ショウブ: name length field at Data offset 605, the
            // character id still at 390). A capture of あこ～ from another
            // player has it at 609 with the id at 394 (4 bytes added before
            // the id); it is not known yet whether that is a newer client
            // version or something that varies per character, so all three
            // are tried. 575 stays last so a client that hasn't updated still
            // parses.
            0x01 => (EntityKind.Player,  PlayerOffsets),
            0x02 => (EntityKind.Monster, MonsterOffsets),   // confirmed via monster_5 capture
            0x04 => (EntityKind.Npc,     CharacterOffsets), // inferred, shares Player's shift
            0x81 => (EntityKind.Party,   PartyOffsets),     // inferred, shares Player's shift
            0x82 => (EntityKind.Party,   PartyOffsets),
            0x83 => (EntityKind.Party,   PartyOffsets),
            0x85 => (EntityKind.Fellow,  PartyOffsets),     // inferred, shares Player's shift
            0x86 => (EntityKind.PartyNpc, CharacterOffsets),  // confirmed via ドルタム capture
            0x87 => (EntityKind.PartyNpc, CharacterOffsets),  // confirmed via エステラ/ギルガラン captures
            0x89 => (EntityKind.PartyNpc, CharacterOffsets),  // confirmed via ユーライザ capture
            0x8A => (EntityKind.PartyNpc, CharacterOffsets),  // confirmed via アンルシア capture
            0x8B => (EntityKind.PartyNpc, CharacterOffsets),  // confirmed via ラダ・ガート capture
            0x24 => (EntityKind.ScoutableMonster, MonsterOffsets), // confirmed via a scoutable
                                                          // field monster's capture
                                                          // (name landed at the exact
                                                          // same offset as Monster's)
            _    => (EntityKind.None,    Array.Empty<int>()),
        };

        if (_kind == EntityKind.None) return;
        Parse();
    }

    private void Parse()
    {
        _headerOffset = -1;
        foreach (var candidate in _headerOffsets)
        {
            if (NameFitsAt(candidate)) { _headerOffset = candidate; break; }
        }

        // None of the known offsets fit: the header may have grown again.
        if (_headerOffset < 0) _headerOffset = ScanForName();

        // The character id is reported independently of whether the name can
        // be translated, so PlayerContext still identifies the logged-in
        // character even if the name can't be located (see the nameplate-
        // toggle note above). Its offset follows the name's layout: it is
        // read at 390 for the 575 layout and 215 bytes before the name for 605 and up.
        if (_kind == EntityKind.Player)
        {
            var idOffset = _headerOffset >= 605 ? _headerOffset - CharacterIdBeforeName : CharacterIdOffset;
            if (_raw.Length >= idOffset + 4)
            {
                var characterId = BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(idOffset, 4));
                _deps.PlayerContext.NotifyEntityId(characterId, _deps);
            }
        }

        if (_headerOffset < 0)
        {
            var kind = _kind;
            _kind = EntityKind.None;

            // An entity with no usable name is normal for some NPCs and is just
            // left alone. But if the packet carries Japanese text somewhere, a
            // name almost certainly exists and has moved: report it (this throw
            // is caught by PacketGuard) rather than silently doing nothing, so
            // the next layout change is noticed when it happens.
            var elsewhere = LayoutDiagnostics.FindStrings(_raw, 3);
            if (elsewhere.Count > 0)
                throw new PacketLayoutException(
                    $"{kind} entity: no name at the expected offsets ({string.Join("/", _headerOffsets)}) " +
                    $"or up to {ScanMaxBytes} bytes past them, " +
                    $"but text \"{elsewhere[0].Text}\" is at offset {elsewhere[0].Offset}",
                    elsewhere[0].Offset);
            return;
        }

        var reader = new PacketReader(_raw);
        _header = reader.ReadBytes(_headerOffset).ToArray();
        _ = reader.ReadU32(); // entity_length — recomputed on write
        _entityName = reader.ReadCString();
        _remainder = reader.RemainingBytes().ToArray();
    }

    // Last resort when none of the listed offsets fits: try each listed offset
    // plus 4, 8, ... up to ScanMaxBytes (the header has so far only ever grown, in
    // whole u32s), nearest first, and take the first spot where a name fits. A
    // name found this way must contain Japanese text -- looser matching than the
    // listed offsets, so it is held to a stricter test, and an already-translated
    // (English) packet falls through to "no name", as it always has. -1 if none.
    private int ScanForName()
    {
        var tried = new HashSet<int>(_headerOffsets);
        var candidates = new SortedSet<int>();
        foreach (var baseOffset in _headerOffsets)
            for (var extra = ScanStepBytes; extra <= ScanMaxBytes; extra += ScanStepBytes)
                if (!tried.Contains(baseOffset + extra)) candidates.Add(baseOffset + extra);

        foreach (var candidate in candidates)
            if (NameFitsAt(candidate, requireJapanese: true)) return candidate;
        return -1;
    }

    // True when a plausible entity_length + name starts at headerOffset: the
    // length is 2..MaxNameBytes (at least one character plus the null), the
    // byte at the end of that span is the null terminator and the only one,
    // and the bytes before it are valid UTF-8 with no control characters
    // (other than the \x04 prefix a translated name carries).
    private bool NameFitsAt(int headerOffset, bool requireJapanese = false)
    {
        if (_raw.Length < headerOffset + 4 + 2) return false;

        var length = BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(headerOffset, 4));
        if (length < 2 || length > MaxNameBytes || headerOffset + 4 + length > _raw.Length) return false;

        var span = _raw.AsSpan(headerOffset + 4, (int)length);
        if (span[^1] != 0) return false;

        var text = span[..^1];
        if (text.IndexOf((byte)0) >= 0) return false;

        try
        {
            var name = new UTF8Encoding(false, true).GetString(text);
            foreach (var c in name)
                if (c < ' ' && c != '\x04') return false;
            if (requireJapanese && !PacketText.HasJapanese(name)) return false;
        }
        catch (DecoderFallbackException) { return false; }

        return true;
    }

    public void Build()
    {
        if (_kind == EntityKind.None) return;

        // A hidden-name job abbreviation: just add the \x04 prefix. Done before
        // the nameplate toggles and the dictionary/romaji lookups -- it isn't a
        // translation (the toggles are about those), and romaji would turn
        // "WAR" into "War". A name that already carries the prefix is not in
        // the set, so the hook re-reading its own write falls through to the
        // per-kind guards below and is left alone.
        if ((_kind == EntityKind.Player || _kind == EntityKind.Party) &&
            ClassAbbreviations.Contains(_entityName))
        {
            WriteName("\x04" + _entityName);
            return;
        }

        string newName;
        switch (_kind)
        {
            case EntityKind.Player:
            {
                if (!_deps.TranslatePlayerNameplates) return;
                // \x04 prefix on the written name means we already processed this
                // packet — the hook re-intercepted its own modified write. bail out
                // to avoid an infinite loop.
                if (_entityName.StartsWith('\x04')) return;
                var playerDict = _deps.M00Dict("local_player_names");
                if (playerDict.TryGetValue(_entityName, out var knownName) && !string.IsNullOrEmpty(knownName))
                    newName = "\x04" + knownName;
                else
                    newName = "\x04" + _deps.Romanizer.ToRomaji(_entityName);
                break;
            }

            case EntityKind.Party:
            {
                if (!_deps.TranslateNpcNameplates) return;
                // \x04 prefix keeps the game from showing the GM-face icon.
                // same re-interception guard as Player.
                if (_entityName.StartsWith('\x04')) return;
                // Player-name dict first, then the custom NPC name overrides
                // (same order as Fellow), romaji fallback only when the party
                // member isn't in either.
                var partyDict = _deps.M00Dict("local_player_names");
                var partyOverrideDict = _deps.M00Dict("custom_npc_name_overrides");
                if (partyDict.TryGetValue(_entityName, out var knownPartyName) && !string.IsNullOrEmpty(knownPartyName))
                    newName = "\x04" + knownPartyName;
                else if (partyOverrideDict.TryGetValue(_entityName, out var partyOverrideName) && !string.IsNullOrEmpty(partyOverrideName))
                    newName = "\x04" + partyOverrideName;
                else
                    newName = "\x04" + _deps.Romanizer.ToRomaji(_entityName);
                break;
            }

            case EntityKind.Npc:
                if (!_deps.TranslateNpcNameplates) return;
                // already translated — hook re-intercepted its own modified write.
                if (!Translator.IsTextJapanese(_entityName)) return;
                var npcDict = _deps.NpcNameDict();
                if (!npcDict.TryGetValue(_entityName, out var npcName) || string.IsNullOrEmpty(npcName)) return;
                newName = npcName;
                break;

            case EntityKind.Monster:
            case EntityKind.ScoutableMonster:
            {
                if (!_deps.TranslateMonsterNameplates) return;
                // already translated — hook re-intercepted its own modified write.
                if (!Translator.IsTextJapanese(_entityName)) return;
                var monsterDict = _deps.M00Dict("monsters");
                if (!monsterDict.TryGetValue(_entityName, out var monsterName) || string.IsNullOrEmpty(monsterName)) return;
                newName = monsterName;
                break;
            }

            case EntityKind.Fellow:
            {
                if (!_deps.TranslateNpcNameplates) return;
                // \x04 prefix on the written name means we already processed this
                // packet — the hook re-intercepted its own modified write. Bail out
                // to avoid an infinite loop (same guard as Player/Party).
                if (_entityName.StartsWith('\x04')) return;
                var fellowPlayerDict = _deps.M00Dict("local_player_names");
                var fellowOverrideDict = _deps.M00Dict("custom_npc_name_overrides");
                if (fellowPlayerDict.TryGetValue(_entityName, out var fellowPlayerName) && !string.IsNullOrEmpty(fellowPlayerName))
                    newName = "\x04" + fellowPlayerName;
                else if (fellowOverrideDict.TryGetValue(_entityName, out var fellowOverrideName) && !string.IsNullOrEmpty(fellowOverrideName))
                    newName = "\x04" + fellowOverrideName;
                else
                    newName = "\x04" + _deps.Romanizer.ToRomaji(_entityName);
                break;
            }

            case EntityKind.PartyNpc:
            {
                if (!_deps.TranslateNpcNameplates) return;
                // \x04 prefix on the written name means we already processed this
                // packet — the hook re-intercepted its own modified write. Bail out
                // to avoid an infinite loop (same guard as Player/Party/Fellow).
                if (_entityName.StartsWith('\x04')) return;
                // No player-name-dict tier here (unlike Fellow) -- these are
                // quest/event NPCs added directly to the party, never a hired
                // player character, so there's no player name they could match.
                var partyNpcDict = _deps.M00Dict("custom_npc_name_overrides");
                if (partyNpcDict.TryGetValue(_entityName, out var partyNpcName) && !string.IsNullOrEmpty(partyNpcName))
                    newName = "\x04" + partyNpcName;
                else
                    newName = "\x04" + _deps.Romanizer.ToRomaji(_entityName);
                break;
            }

            default:
                return;
        }

        if (newName == _entityName) return;

        WriteName(newName);
    }

    private void WriteName(string newName)
    {
        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        var bytes = Encoding.UTF8.GetBytes(newName);
        writer.WriteU32((uint)(bytes.Length + 1)); // include null terminator in length
        writer.WriteCString(newName);
        writer.WriteBytes(_remainder);
        ModifiedData = writer.Build();
    }
}
