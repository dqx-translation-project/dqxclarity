from hooking.hooks.packets.buffer import PacketReader
from hooking.hooks.packets.types.entities.fellow_monster import EntityFellowMonsterPacket
from hooking.hooks.packets.types.entities.monster import EntityMonsterPacket
from hooking.hooks.packets.types.entities.npc import EntityNpcPacket
from hooking.hooks.packets.types.entities.player import EntityPlayerPacket


class EntityPacket:
    """
    Replaces the name in an Entity packet. Each entity is handled
    slightly different. Instead of cramming in a bunch of conditionals
    into a single file, these are broken up into multiple classes to make
    it easier to read. This does duplicate things, but readability is more
    important.
    """
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.raw = raw
        self.modified_data = None

        reader.seek(11)
        type_byte = reader.read_bytes(1)

        entity_types = {
            b"\x01": "player",
            b"\x02": "monster",
            b"\x04": "npc",
            b"\x85": "fellow",
        }

        self.entity_type = entity_types.get(type_byte, b"")

        if not self.entity_type:
            return

        match self.entity_type:
            case "player":
                self.data = EntityPlayerPacket(self.raw)
            case "monster":
                self.data = EntityMonsterPacket(self.raw)
            case "npc":
                self.data = EntityNpcPacket(self.raw)
            case "fellow":
                self.data = EntityFellowMonsterPacket(self.raw)

        self.entity_name = self.data.entity_name


    def build(self) -> bytes:
        # not an entity we are aware of.
        if not self.entity_type:
            return

        # entity matched, but was incomplete.
        if self.data.invalid_entity:
            return

        # look up entity name and pass to self.data.build()
        self.data.build("skdl")
        self.modified_data = self.data.modified_data
