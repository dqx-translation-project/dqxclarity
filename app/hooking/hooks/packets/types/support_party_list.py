import struct
from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class SupportyPartyListPacket:
    def __init__(self, raw: bytes):
        self.modified_data = None

        reader = PacketReader(raw)

        self.header = reader.read_bytes(28)
        self.num_party_members = struct.unpack("<B", self.header[24:25])[0]

        if self.num_party_members == 0:
            return

        self.party_members = []
        for i in range(self.num_party_members):
            header = reader.read_bytes(21)

            # names have a fixed buffer size of 20 bytes.
            # if the name is shorter than 20, there is junk
            # data in the buffer we throw away.
            name = reader.read_bytes(20).split(b"\x00")[0].decode("utf-8")

            self.party_members.append((header, name))

        self.remaining = reader.remaining()

    def __pad(self, string: str):
        str_len = len(string.encode("utf-8"))

        # 20 is the buffer size allocated for names
        difference = 20 - str_len - 1  # leave one off for null terminiator.

        return string + ("\x00" * difference)

    def build(self):
        # leave the packet alone. nothing for us to translate.
        if self.num_party_members == 0:
            return

        writer = PacketWriter()
        writer.write_bytes(self.header)

        for header, name in self.party_members:
            writer.write_bytes(header)
            writer.write_cstring(self.__pad("dsfgsdgf"[:11]))

        writer.write_bytes(self.remaining)

        self.modified_data = writer.build()
