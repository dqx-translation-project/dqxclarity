from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class MyTownAmenityPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)

        # read data up to first string
        self.header_data = reader.read_bytes(12)
        self.name = reader.read_cstring()

        self.modified_data = None

    def build(self) -> bytes:
        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        # replace self.name with translated name here.
        writer.write_cstring("fdgsdgsdfgsdfg")

        self.modified_data = writer.build()
