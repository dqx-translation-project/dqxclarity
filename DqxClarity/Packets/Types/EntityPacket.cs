using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// One packet wire-format with a type discriminator at offset 11. Type byte
// dictates two things: (1) what header_offset to use before the name field
// (NPC/Player/Party/Fellow=574, Monster=401), (2) how the name is resolved:
//   Player  — local_player_names m00 dict → romanizer fallback, \x04 prefix
//   Party   — romanizer, \x04 prefix
//   NPC     — npc name dict, pass-through on miss
//   Monster — monsters m00 dict, pass-through on miss (no romanizer fallback)
//   Fellow  — pass-through
//
// Layout:
//   header_data           header_offset bytes
//   entity_length         u32  (utf-8 byte length of entity_name including null)
//   entity_name           cstring
//   remainder             rest of payload
public sealed class EntityPacket : IPacket
{
    private const int TypeByteOffset = 11;

    private enum EntityKind
    {
        None, Player, Monster, Npc, Party, Fellow,
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
            0x01 => (EntityKind.Player,  574),
            0x02 => (EntityKind.Monster, 401),
            0x04 => (EntityKind.Npc,     574),
            0x81 => (EntityKind.Party,   574),
            0x82 => (EntityKind.Party,   574),
            0x83 => (EntityKind.Party,   574),
            0x85 => (EntityKind.Fellow,  574),
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
    }

    public void Build()
    {
        if (_kind == EntityKind.None) return;

        string newName;
        switch (_kind)
        {
            case EntityKind.Player:
            {
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
                // \x04 prefix keeps the game from showing the GM-face icon.
                // same re-interception guard as Player.
                if (_entityName.StartsWith('\x04')) return;
                newName = "\x04" + _deps.Romanizer.ToRomaji(_entityName);
                break;

            case EntityKind.Npc:
                // already translated — hook re-intercepted its own modified write.
                if (!Translator.IsTextJapanese(_entityName)) return;
                var npcDict = _deps.NpcNameDict();
                if (!npcDict.TryGetValue(_entityName, out var npcName) || string.IsNullOrEmpty(npcName)) return;
                newName = npcName;
                break;

            case EntityKind.Monster:
            {
                // already translated — hook re-intercepted its own modified write.
                if (!Translator.IsTextJapanese(_entityName)) return;
                var monsterDict = _deps.M00Dict("monsters");
                if (!monsterDict.TryGetValue(_entityName, out var monsterName) || string.IsNullOrEmpty(monsterName)) return;
                newName = monsterName;
                break;
            }

            case EntityKind.Fellow:
                return;

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
