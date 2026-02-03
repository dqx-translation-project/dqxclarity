from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class MemoryListSubChaptersPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.modified_data = None

        self.num_times_opened = reader.read_u32()
        self.padding = reader.read_bytes(4)
        self.num_sub_chapters = reader.read_u32()

        self.sub_chapters = []
        for _ in range(self.num_sub_chapters):
            unknown_1 = reader.read_u32()
            unknown_2 = reader.read_u32()
            name = reader.read_cstring()
            self.sub_chapters.append([unknown_1, unknown_2, name])

    def build(self) -> bytes:
        writer = PacketWriter()

        writer.write_u32(self.num_times_opened)
        writer.write_bytes(self.padding)
        writer.write_u32(self.num_sub_chapters)

        for unk1, unk2, name in self.sub_chapters:
            writer.write_u32(unk1)
            writer.write_u32(unk2)

            if not name:
                writer.write_bytes(b"\x00")
            else:
                # look up name to replace with...
                writer.write_cstring("some sub chapter")

        self.modified_data = writer.build()
