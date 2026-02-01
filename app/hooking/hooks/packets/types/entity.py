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
        self.raw = raw
        self.modified_data = None
        self.entity_type = None

        type_byte = raw[11:12]

        match type_byte:
            case b"\x01":
                self.data = EntityPlayerPacket(self.raw)
                self.entity_type = "player"
            case b"\x02":
                self.data = EntityMonsterPacket(self.raw)
                self.entity_type = "monster"
            case b"\x04":
                self.data = EntityNpcPacket(self.raw)
                self.entity_type = "npc"
            case b"\x85":
                self.data = EntityFellowMonsterPacket(self.raw)
                self.entity_type = "fellow"
            case _:
                return

        if self.data.invalid_entity:
            return

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
