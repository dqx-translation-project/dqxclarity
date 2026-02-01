from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class TeamQuestPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)

        # read data up to first string
        self.header_data = reader.read_bytes(76)

        # team quests always come in pairs.
        self.quest_1_name = reader.read_cstring()
        self.quest_1_desc = reader.read_cstring()
        self.quest_2_name = reader.read_cstring()
        self.quest_2_desc = reader.read_cstring()

        self.modified_data = None

    def build(self) -> bytes:
        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        # translate self.quest_1_name, desc, etc. here.
        # write the translated strings or the original text
        # to the buffer.
        writer.write_cstring("skjgsdkjgsdjkng")
        writer.write_cstring("skdjfgkjsdgskjdngf")
        writer.write_cstring("kjhsdbgjksdbgsjhkbdg")
        writer.write_cstring("jkasbfbhsghjbdgf")

        self.modified_data = writer.build()
