from common.translate import transliterate_player_name
from hooking.hooks.packets.buffer import PacketReader, PacketWriter
from loguru import logger as log


class EntityPlayerPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.modified_data = None
        self.entity_offset = 574

        # read up to name data.
        self.header_data = reader.read_bytes(self.entity_offset)

        # get entity info.
        self.entity_length = reader.read_u32()
        self.entity_name = reader.read_cstring()

        # get remaining data.
        self.remaining = reader.remaining()

    def build(self, name: str):
        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        name = "\x04" + transliterate_player_name(name)
        name_length = len(name.encode("utf-8")) + 1  # include NT.

        writer.write_u32(name_length)
        writer.write_cstring(name)

        log.debug(f"Updated player: {self.entity_name} => {name}.")

        writer.write_bytes(self.remaining)

        self.modified_data = writer.build()
