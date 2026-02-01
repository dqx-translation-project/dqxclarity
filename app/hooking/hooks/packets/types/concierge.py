from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class ConciergePacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)

        # read data up to first string
        self.header_data = reader.read_bytes(221)
        self.name = reader.read_cstring()
        self.remaining = reader.remaining()

        self.modified_data = None

    def build(self) -> bytes:
        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        # replace self.name with translated name here.
        writer.write_cstring("concierge dude")
        writer.write_bytes(self.remaining)

        self.modified_data = writer.build()
