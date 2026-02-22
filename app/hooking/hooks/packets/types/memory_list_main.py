from common.db_ops import generate_m00_dict
from hooking.hooks.packets.buffer import PacketReader, PacketWriter


# replace when we implement this.
_memory_list = generate_m00_dict("'quests'")


class MemoryListMainPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)

        # read data up to first string
        self.header_data = reader.read_bytes(12)

        # all strings are listed here.
        text = reader.remaining().split(b"\x00")

        self.text_list = [s for s in text if s]

        self.modified_data = None

    def __translate(self, text: str) -> str:
        return _memory_list.get(text, text)

    def build(self) -> bytes:
        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        # lookup chapter and replace. otherwise, return jp.
        # string can only be 29 characters long. any longer
        # and the window will lock up.
        for chapter in self.text_list:
            trl_name = self.__translate(chapter.decode("utf-8"))
            writer.write_cstring(trl_name[:29])

        self.modified_data = writer.build()
