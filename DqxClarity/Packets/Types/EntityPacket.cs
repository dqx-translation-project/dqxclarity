using System.Buffers.Binary;
using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// One packet wire-format with a type discriminator at offset 11. Type byte
// dictates two things: (1) what header_offset to use before the name field
// (NPC/Player/Party/Fellow=575, Monster/ScoutableMonster=402 — a game update
// inserted one byte somewhere in each kind's header, shifting these +1 from
// the original 574/401. Confirmed independently via captured packets for
// Player and Monster; Npc/Party/Fellow are inferred to share Player's shift
// since they use the same 574-origin offset, but haven't been captured
// post-update), (2) how the name is resolved:
//   Player           — local_player_names m00 dict → romanizer fallback, \x04 prefix
//   Party            — local_player_names m00 dict → romanizer fallback, \x04 prefix
//                      (same resolution as Player -- a party member entity is
//                      still a player, so a name override set for that player
//                      elsewhere should apply here too, not just the romaji
//                      fallback)
//   NPC              — npc name dict, pass-through on miss
//   Monster          — monsters m00 dict, pass-through on miss (no romanizer fallback)
//   ScoutableMonster — same as Monster (see type byte 0x24 below)
//   Fellow           — local_player_names m00 dict, then custom_npc_name_overrides
//                      m00 dict, romanizer fallback on miss in both, \x04 prefix
//                      (confirmed via a ガヴァ capture that stayed untranslated
//                      with no dict match, and a hired フェロー whose translated
//                      name rendered without the GM-face-icon prevention prefix)
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
//   NPC nameplates     -> gates EntityKind.Npc, Party, AND Fellow (a party
//                         member is still rendered as a name-tagged
//                         character the same way an NPC is, and a Fellow is
//                         the same kind of "non-monster companion" nameplate)
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
    private const int CharacterIdOffset = 390; // only meaningful for EntityKind.Player

    private enum EntityKind
    {
        None, Player, Monster, Npc, Party, Fellow, ScoutableMonster,
    }

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private EntityKind _kind = EntityKind.None;
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

        (_kind, _headerOffset) = typeByte switch
        {
            0x01 => (EntityKind.Player,  575),   // confirmed via player captures
            0x02 => (EntityKind.Monster, 402),   // confirmed via monster_5 capture
            0x04 => (EntityKind.Npc,     575),   // inferred, shares Player's shift
            0x81 => (EntityKind.Party,   575),   // inferred, shares Player's shift
            0x82 => (EntityKind.Party,   575),
            0x83 => (EntityKind.Party,   575),
            0x85 => (EntityKind.Fellow,  575),   // inferred, shares Player's shift
            0x24 => (EntityKind.ScoutableMonster, 402), // confirmed via a scoutable
                                                          // field monster's capture
                                                          // (name landed at the exact
                                                          // same offset as Monster's)
            _    => (EntityKind.None,    0),
        };

        if (_kind == EntityKind.None) return;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < _headerOffset + 4) { _kind = EntityKind.None; return; }
        var reader = new PacketReader(_raw);
        _header = reader.ReadBytes(_headerOffset).ToArray();
        _ = reader.ReadU32(); // entity_length — recomputed on write
        _entityName = reader.ReadCString();
        _remainder = reader.RemainingBytes().ToArray();

        if (_kind == EntityKind.Player && _raw.Length >= CharacterIdOffset + 4)
        {
            var characterId = BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(CharacterIdOffset, 4));
            _deps.PlayerContext.NotifyEntityId(characterId, _deps);
        }
    }

    public void Build()
    {
        if (_kind == EntityKind.None) return;

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
                // Same resolution as Player: name override dict first, romaji
                // fallback only when the party member isn't in it.
                var partyDict = _deps.M00Dict("local_player_names");
                if (partyDict.TryGetValue(_entityName, out var knownPartyName) && !string.IsNullOrEmpty(knownPartyName))
                    newName = "\x04" + knownPartyName;
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

            default:
                return;
        }

        if (newName == _entityName) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        var bytes = Encoding.UTF8.GetBytes(newName);
        writer.WriteU32((uint)(bytes.Length + 1)); // include null terminator in length
        writer.WriteCString(newName);
        writer.WriteBytes(_remainder);
        ModifiedData = writer.Build();
    }
}
