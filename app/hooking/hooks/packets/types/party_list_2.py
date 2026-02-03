from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class PartyList2Packet:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.modified_data = None
        self.header_data = reader.read_bytes(80)

        # name has a 41 byte fixed buffer.
        self.name = reader.read_bytes(41).decode("utf-8").rstrip("\x00")
        self.remaining = reader.remaining()

    def __pad(self, string: str):
        str_len = len(string.encode("utf-8"))

        # 41 is the buffer size allocated for names
        difference = 41 - str_len - 1  # leave one off for null terminiator.

        return string + ("\x00" * difference)

    def build(self):
        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        # lookup name: self.name
        writer.write_cstring(self.__pad("partylisttwo"[:11]))

        writer.write_bytes(self.remaining)

        self.modified_data = writer.build()
