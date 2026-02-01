from hooking.hooks.packets.buffer import PacketReader, PacketWriter
from loguru import logger as log


class EntityPlayerPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.modified_data = None
        self.invalid_entity = False
        self.entity_offset = 574

        # here for protection as there are so many variations.
        if len(raw) < self.entity_offset:
            self.invalid_entity = True
            return

        # read up to name data.
        self.header_data = reader.read_bytes(self.entity_offset)

        # get entity info.
        self.entity_length = reader.read_u32()
        self.entity_name = reader.read_cstring()

        # get remaining data.
        self.remaining = reader.remaining()

    def build(self, name: str):
        if self.invalid_entity:
            return

        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        # name should be no longer than 11 bytes. any more can cause crashes.
        # lookup name: self.entity_name
        name = name[:11]
        name_length = len(name.encode('utf-8')) + 1  # include NT.

        writer.write_u32(name_length)
        writer.write_cstring(name)

        log.debug(f"Updated player: {self.entity_name} => {name}.")

        writer.write_bytes(self.remaining)

        self.modified_data = writer.build()
