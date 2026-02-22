from common.db_ops import generate_m00_dict
from hooking.hooks.packets.buffer import PacketReader, PacketWriter


# replace when we implement this.
_memory_list = generate_m00_dict("'quests'")


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

    def __translate(self, text: str) -> str:
        return _memory_list.get(text, text)

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
                trl_name = self.__translate(name)
                writer.write_cstring(trl_name[:29])

        writer.write_u32(self.num_stories)

        for val, name in self.stories:
            writer.write_u32(val)

            if not name:
                writer.write_bytes(b"\x00")
            else:
                trl_name = self.__translate(name)
                writer.write_cstring(trl_name[:29])

        self.modified_data = writer.build()
