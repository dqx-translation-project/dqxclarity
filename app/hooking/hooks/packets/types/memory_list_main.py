from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class MemoryListMainPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)

        # read data up to first string
        self.header_data = reader.read_bytes(12)

        # all strings are listed here.
        text = reader.remaining().split(b"\x00")

        self.text_list = [s for s in text if s]

        self.modified_data = None

    def build(self) -> bytes:
        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        # lookup chapter and replace. otherwise, return jp.
        # string can only be 29 characters long. any longer
        # and the window will lock up.
        for chapter in self.text_list:
            writer.write_cstring("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"[:29])

        self.modified_data = writer.build()
