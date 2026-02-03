from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class PartyList3Packet:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.modified_data = None
        self.header_data = reader.read_bytes(78)

        # read over length. we will build our own
        self.name_length = reader.read_u32()

        # there's no name, don't build.
        if self.name_length == 0:
            return

        self.name = reader.read_cstring()

        self.remaining = reader.remaining()

    def build(self):
        if not self.name_length:
            return

        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        # lookup name: self.name
        name = "partylistthree"[:11]
        name_length = len(name.encode("utf-8")) + 1  # include NT.

        writer.write_u32(name_length)
        writer.write_cstring(name)
        writer.write_bytes(self.remaining)

        self.modified_data = writer.build()
