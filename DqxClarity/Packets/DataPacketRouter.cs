using DqxClarity.Packets.Types;

namespace DqxClarity.Packets;

// Payload layout (post-segment-header): [op_code:1][marker:2][data:...].
// We dispatch on the (op_code, marker) pair to a packet-type class. The packet
// type optionally serialises a new payload-data buffer; we then return
// op_code + marker + new_data as the modified payload.
public sealed class DataPacketRouter
{
    public delegate IPacket? Dispatcher(byte opCode, ushort marker, byte[] payloadData);

    private readonly byte[] _payload;

    public byte OpCode { get; }
    public ushort Marker { get; }
    public byte[] Data { get; }

    public byte[]? ModifiedData { get; private set; }
    public int ModifiedSize { get; private set; }

    public DataPacketRouter(byte[] payload)
    {
        _payload = payload;
        OpCode = payload[0];
        Marker = (ushort)((payload[1] << 8) | payload[2]);
        Data = new byte[payload.Length - 3];
        Buffer.BlockCopy(payload, 3, Data, 0, Data.Length);
    }

    public void Parse(Dispatcher dispatcher)
    {
        IPacket? packet = dispatcher(OpCode, Marker, Data);
        if (packet == null) return;

        packet.Build();
        if (packet.ModifiedData == null) return;

        var newData = packet.ModifiedData;
        var total = new byte[3 + newData.Length];
        total[0] = OpCode;
        total[1] = (byte)((Marker >> 8) & 0xFF);
        total[2] = (byte)(Marker & 0xFF);
        Buffer.BlockCopy(newData, 0, total, 3, newData.Length);
        ModifiedData = total;
        ModifiedSize = total.Length;
    }

    public static string GetPacketName(byte opCode, ushort marker, byte[]? payloadData = null) =>
        (opCode, marker) switch
        {
            (0x21, 0xa83c) => "NpcDialogue",
            (0x21, 0x9804) => "NpcDialogueNoName",
            (0x21, 0xbe01) => "StorySoFarText",
            (0x21, 0x5878) => "Walkthrough",
            (0x5d, 0x2b15) => "QuestAccept",
            (0x5d, 0xcc51) => "QuestLog",
            (0x87, 0x5408) => "ServerList",
            (0x87, 0x8408) => "ServerList",
            (0x87, 0x6185) => "ImportantNotice",
            (0x87, 0xf7f5) => "CharacterLogList",
            (0x87, 0x0e23) => "DeleteAdventureLog_Check",
            (0x87, 0x12c6) => "LoginPresentList",
            (0x87, 0xdb19) => "LoginLoginStatus",
            (0x87, 0x0eb8) => "LoginAssistantAi",
            (0x05, 0x2b66) => "Concierge",
            (0x4b, 0x4569) => "MyTownAmenity",
            (0x79, 0x994b) => "MasterQuest",
            (0x3d, 0x16b6) => "TeamQuest",
            (0x46, 0x6bb8) => "WeeklyRequest",
            (0x0d, 0x9ee1) => "CommWindowList",
            (0x0d, 0x2711) => "Chat_Team",
            (0x1d, 0x732b) => "Chat_Say",
            (0x0d, 0x7690) => "Chat_Friends",
            (0x0d, 0xee25) => "Chat_Party",
            (0x0d, 0x755d) => "Chat_RoomA",
            (0x03, 0xf7f5) => "PartyList",
            (0x52, 0xee25) => GetEntitySubType(payloadData),
            (0x03, 0x5408) => "PartyList2",
            (0xa1, 0x2711) => "PartyList3",
            (0xa1, 0x8a6a) => "PartyList4",
            (0xaa, 0x7a64) => "SupportPartyList",
            (0xaa, 0xde02) => "TavernRecruitmentList",
            (0x66, 0x4cc2) => "MemoryListMain",
            (0x66, 0xda30) => "MemoryListChapters",
            (0x66, 0x4569) => "MemoryListSubChapters",
            _ => $"0x{opCode:X2} 0x{marker:X4}",
        };

    private static string GetEntitySubType(byte[]? data)
    {
        if (data == null || data.Length <= 11) return "Entity";
        return data[11] switch
        {
            0x01 => "Entity (Player)",
            0x02 => "Entity (Monster)",
            0x04 => "Entity (NPC)",
            0x81 or 0x82 or 0x83 => "Entity (Party)",
            0x85 => "Entity (Fellow)",
            var b => $"Entity (0x{b:X2})",
        };
    }

    public static Dispatcher BuildDefaultDispatcher(PacketDependencies deps) =>
        (op, marker, data) => (op, marker) switch
        {
            (0x21, 0xa83c) => new NpcDialoguePacket(data, deps, NpcDialoguePacket.Variant.WithName),
            (0x21, 0x9804) => new NpcDialoguePacket(data, deps, NpcDialoguePacket.Variant.NoName),
            (0x21, 0xbe01) => new StorySoFarTextPacket(data, deps),
            (0x21, 0x5878) => new WalkthroughPacket(data, deps),
            (0x5d, 0x2b15) => new QuestPacket(data, deps, QuestPacket.Variant.Accept),
            (0x5d, 0xcc51) => new QuestPacket(data, deps, QuestPacket.Variant.Log),
            (0x87, 0x5408) => new ServerListPacket(data, deps),
            (0x87, 0x8408) => new ServerListPacket(data, deps),
            (0x05, 0x2b66) => new ConciergePacket(data, deps),
            (0x4b, 0x4569) => new MyTownAmenityPacket(data, deps),
            (0x79, 0x994b) => new MasterQuestPacket(data, deps),
            (0x3d, 0x16b6) => new TeamQuestPacket(data, deps),
            (0x46, 0x6bb8) => new WeeklyRequestPacket(data, deps),
            (0x0d, 0x9ee1) => new CommWindowListPacket(data, deps),
            (0x03, 0xf7f5) => new PartyListPacket(data, deps),
            (0x52, 0xee25) => new EntityPacket(data, deps),
            (0x03, 0x5408) => new PartyList2Packet(data, deps),
            (0xa1, 0x2711) => new PartyList3Packet(data, deps),
            (0xa1, 0x8a6a) => new PartyList4Packet(data, deps),
            (0xaa, 0x7a64) => new SupportPartyListPacket(data, deps),
            (0x66, 0x4cc2) => new MemoryListMainPacket(data, deps),
            (0x66, 0xda30) => new MemoryListChaptersPacket(data, deps),
            (0x66, 0x4569) => new MemoryListSubChaptersPacket(data, deps),
            _ => null,
        };
}

// Bundle of services a packet type needs to do its job. Passed through the
// router rather than rooted in static state so tests can substitute fakes.
public sealed class PacketDependencies
{
    public required Data.ClarityDb Db { get; init; }
    public required Translation.Translator Translator { get; init; }
    public required Translation.IRomanizer Romanizer { get; init; }

    // Cache of m00_strings lookups, keyed by the comma-separated `files` filter. Lazy-load on first access.
    private readonly Dictionary<string, Dictionary<string, string>> _m00Cache = new();
    public Dictionary<string, string> M00Dict(params string[] files)
    {
        var key = string.Join(',', files);
        if (!_m00Cache.TryGetValue(key, out var dict))
        {
            dict = Db.LoadM00Strings(files);
            _m00Cache[key] = dict;
        }
        return dict;
    }

    // NPC name lookup: base names from 'npcs', then custom overrides layered on top.
    // Loaded separately to guarantee override ordering (LoadM00Strings uses IN with
    // no ORDER BY, so a single call can't guarantee which file's value wins).
    private Dictionary<string, string>? _npcNameCache;
    public Dictionary<string, string> NpcNameDict()
    {
        if (_npcNameCache != null) return _npcNameCache;
        var dict = Db.LoadM00Strings(new[] { "npcs" });
        foreach (var kv in Db.LoadM00Strings(new[] { "custom_npc_name_overrides" }))
            dict[kv.Key] = kv.Value;
        _npcNameCache = dict;
        return dict;
    }
}
