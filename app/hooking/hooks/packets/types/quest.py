from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class QuestPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)

        self.num_times_opened = reader.read_u32()
        self.padding = reader.read_bytes(4)
        self.unknown_1 = reader.read_u16()
        self.quest_number = reader.read_u32()
        self.unknown_2 = reader.read_u32()
        self.unknown_3 = reader.read_u32()
        self.unknown_4 = reader.read_u32()

        # quest data is placed in fixed buffer sizes. easier to
        # read the fixed buffer lengths and clean up the data.
        self.quest_chapter = reader.read_bytes(56).decode('utf-8').rstrip('\x00')
        self.quest_name = reader.read_bytes(56).decode('utf-8').rstrip('\x00')
        self.quest_description = reader.read_bytes(508).decode('utf-8').rstrip('\x00')
        self.reward_1 = reader.read_bytes(104).decode('utf-8').rstrip('\x00')
        self.reward_2 = reader.read_bytes(104).decode('utf-8').rstrip('\x00')

        self.remaining = reader.remaining()

        self.modified_text = None
        self.modified_data = None

    def __pad(self, string: str, count: int):
        str_len = len(string.encode('utf-8'))
        difference = count - str_len - 1  # leave one off for null terminiator.

        return string + ("\x00" * difference)

    def build(self) -> bytes:
        writer = PacketWriter()

        # would replace with code that translates text.
        self.quest_description = "yummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummyyummy"

        writer.write_u32(self.num_times_opened)
        writer.write_bytes(b'\x00' * 4)
        writer.write_u16(self.unknown_1)
        writer.write_u32(self.quest_number)
        writer.write_u32(self.unknown_2)
        writer.write_u32(self.unknown_3)
        writer.write_u32(self.unknown_4)

        # make sure we don't write outside of the fixed buffer.
        writer.write_cstring(self.__pad(self.quest_chapter[:55], 56))
        writer.write_cstring(self.__pad(self.quest_name[:55], 56))
        writer.write_cstring(self.__pad(self.quest_description[:507], 508))
        writer.write_cstring(self.__pad(self.reward_1[:103], 104))
        writer.write_cstring(self.__pad(self.reward_2[:103], 104))

        writer.write_bytes(self.remaining)

        self.modified_data = writer.build()
