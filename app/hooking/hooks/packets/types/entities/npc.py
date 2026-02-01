from hooking.hooks.packets.buffer import PacketReader, PacketWriter
from loguru import logger as log


class EntityNpcPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.modified_data = None
        self.entity_offset = 574

        # read up to name data.
        self.header_data = reader.read_bytes(self.entity_offset)

        # get entity info. this data _looks_ like it's in a fixed buffer,
        # but all of the 00's added at the end of the string are actually
        # necessary. it's an arbitrary length that changes and there is no
        # fixed buffer, so we just need to make sure that same length of 00's
        # is added at the end of every string. so weird. I spent too much time
        # debugging this.
        self.entity_length = reader.read_u32()
        self.entity_name = reader.read_cstring()

        self.remaining = reader.remaining()

    def build(self, name: str):
        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        # unsure what the max name length is here, so we're just
        # going to yolo it until it crashes.
        # lookup name: self.entity_name
        name_length = len(name.encode("utf-8")) + 1  # include NT.

        writer.write_u32(name_length)
        writer.write_cstring(name)
        writer.write_bytes(self.remaining)

        log.debug(f"Updated NPC: {self.entity_name} => {name}.")

        self.modified_data = writer.build()
