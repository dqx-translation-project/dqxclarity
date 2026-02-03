from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class MemoryListChaptersPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.modified_data = None

        self.num_times_opened = reader.read_u32()
        self.padding = reader.read_bytes(4)
        self.num_chapters = reader.read_u32()

        # packet is structured with high level chapters,
        # then any story categories. they do not contain the
        # individual cutscenes themselves.
        self.chapters = []
        for _ in range(self.num_chapters):
            unknown = reader.read_u32()
            name = reader.read_cstring()
            self.chapters.append([unknown, name])

        self.num_stories = reader.read_u32()

        self.stories = []
        for _ in range(self.num_stories):
            unknown = reader.read_u32()
            name = reader.read_cstring()
            self.stories.append([unknown, name])

    def build(self) -> bytes:
        writer = PacketWriter()

        writer.write_u32(self.num_times_opened)
        writer.write_bytes(self.padding)
        writer.write_u32(self.num_chapters)

        for val, name in self.chapters:
            writer.write_u32(val)

            if not name:
                writer.write_bytes(b"\x00")
            else:
                # look up name to replace with...
                writer.write_cstring("another")

        writer.write_u32(self.num_stories)

        for val, name in self.stories:
            writer.write_u32(val)

            if not name:
                writer.write_bytes(b"\x00")
            else:
                # look up name to replace with...
                writer.write_cstring("something")

        self.modified_data = writer.build()
