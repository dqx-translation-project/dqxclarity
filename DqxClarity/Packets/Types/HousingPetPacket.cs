using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// A wandering, pettable monster in a housing area (My Town) -- opcode 0x05,
// marker 0x4a1a. These are tamed/scouted monsters a player has set loose to
// wander their house, each with a player-given nickname rather than a fixed
// species name, so they're resolved the same way as EntityPacket's Fellow
// case (see that class's doc comment) rather than the plain species-name
// 'monsters' m00 dict used by Monster/ScoutableMonster.
//
// Layout (after opcode + marker):
//   header_data    60 bytes (passthrough)
//   name           cstring (utf-8), free-growing -- there's no length
//                  prefix and nothing after it in either capture is a fixed
//                  offset from the name, so like ConciergePacket this is
//                  safe to grow/shrink freely
//   remainder      rest of payload (passthrough; 4 zero bytes in both
//                  captures -- no observed meaning, preserved untouched)
//
// Name resolution: same dict chain as EntityPacket's Fellow case --
// local_player_names m00 dict first, then custom_npc_name_overrides m00
// dict, romanizer fallback on miss in both -- but with no \x04 GM-face-icon
// prefix (not needed for this packet, per the user). Re-interception guard
// is the plain Translator.IsTextJapanese check instead, same as
// HouseSignpostPacket's player name. Gated on NPC nameplates, not monster
// nameplates, again matching Fellow: a Fellow entity can itself be a tamed
// monster with a player-given nickname (see EntityPacket's ガヴァ example),
// so this is the same "named companion" category, not the plain-species
// Monster/ScoutableMonster one.
//
// Samples: docs/packets/references/housing_pet_saber (セイバー, 60-byte
//          header, name at offset 60, 4 trailing zero bytes)
//          docs/packets/references/housing_pet_rockman (ロックマン, same
//          shape, confirming the fixed 60-byte header offset holds
//          regardless of name length)
public sealed class HousingPetPacket : IPacket
{
    private const int HeaderBytes = 60;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _name = "";
    private byte[] _remainder = Array.Empty<byte>();

    public byte[]? ModifiedData { get; private set; }

    public HousingPetPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        if (_raw.Length < HeaderBytes) return;
        var reader = new PacketReader(_raw);
        _header = reader.ReadBytes(HeaderBytes).ToArray();
        _name = reader.ReadCString();
        _remainder = reader.RemainingBytes().ToArray();
    }

    public void Build()
    {
        if (_header.Length < HeaderBytes) return;
        if (!_deps.TranslateNpcNameplates) return;
        // Already translated -- hook re-intercepted its own modified write.
        if (!Translator.IsTextJapanese(_name)) return;

        var playerDict = _deps.M00Dict("local_player_names");
        var overrideDict = _deps.M00Dict("custom_npc_name_overrides");
        var newName = playerDict.TryGetValue(_name, out var knownPlayer) && !string.IsNullOrEmpty(knownPlayer)
            ? knownPlayer
            : overrideDict.TryGetValue(_name, out var knownOverride) && !string.IsNullOrEmpty(knownOverride)
                ? knownOverride
                : _deps.Romanizer.ToRomaji(_name);

        if (newName == _name) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(newName);
        writer.WriteBytes(_remainder);
        ModifiedData = writer.Build();
    }
}
