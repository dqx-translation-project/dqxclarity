from hooking.hooks.packets.buffer import PacketReader, PacketWriter
from loguru import logger as log


class EntityMonsterPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.modified_data = None
        self.invalid_entity = False
        self.entity_offset = 401

        # here for protection as there are so many variations.
        if len(raw) < self.entity_offset:
            self.invalid_entity = True
            return

        # read up to name data.
        self.header_data = reader.read_bytes(self.entity_offset)

        # get entity info. this data _looks_ like it's in a fixed buffer,
        # but all of the 00's added at the end of the string are actually
        # necessary. it's an arbitrary length that changes and there is no
        # fixed buffer, so we just need to make sure that same length of 00's
        # is added at the end of every string.
        self.entity_length = reader.read_u32()
        self.entity_name = reader.read_cstring()

        # get remaining data.
        self.remaining = reader.remaining()

    def build(self, name: str):
        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        # lookup name: self.entity_name
        name_length = len(name.encode("utf-8")) + 1  # include NT.

        writer.write_u32(name_length)
        writer.write_cstring(name)

        writer.write_bytes(self.remaining)

        log.debug(f"Updated monster: {self.entity_name} => {name}.")

        self.modified_data = writer.build()
