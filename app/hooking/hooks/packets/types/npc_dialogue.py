import zlib
from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class NpcDialoguePacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)

        self.num_times_opened = reader.read_u32()
        self.padding = reader.read_bytes(4)
        self.unknown_1 = reader.read_u16()
        self.unknown_2 = reader.read_u16()
        self.text_length = reader.read_u32()
        self.text = reader.read_cstring()
        self.unknown_3 = reader.read_u32()  # length of npc name?
        self.npc_name = reader.read_cstring()
        self.unknown_4 = reader.read_bytes(7)
        self.bitwise = reader.read_u32()  # used to compute crc
        self.crc_value = reader.read_u32()

        self.modified_text = None
        self.modified_data = None

    def __calculate_crc(self, text: str):
        """Calculates a new CRC value for text modified in the built packet."""
        return zlib.crc32(text.encode('utf-8')) & self.bitwise

    def build(self) -> bytes:
        writer = PacketWriter()

        # would replace with code that translates text.
        self.modified_text = self.text.replace("「プッ", "aaaaaaaaaaasdasdasdadsadasdsadasda")  # test that text replace works.

        text = self.modified_text if self.modified_text is not None else self.text

        # add null terminator to length
        text_length = len(text.encode('utf-8')) + 1 if self.modified_text is not None else self.text_length
        crc = self.crc_value if self.modified_text is None else self.__calculate_crc(text)

        writer.write_u32(self.num_times_opened)
        writer.write_bytes(self.padding)
        writer.write_u16(self.unknown_1)
        writer.write_u16(self.unknown_2)
        writer.write_u32(text_length)
        writer.write_cstring(text)
        writer.write_u32(self.unknown_3)
        writer.write_cstring(self.npc_name)
        writer.write_bytes(self.unknown_4)
        writer.write_u32(self.bitwise)
        writer.write_u32(crc)

        self.modified_data = writer.build()
