from hooking.hooks.packets.buffer import PacketReader


class PartyListPacket:
    def __init__(self, raw: bytes):
        self.data = raw
        reader = PacketReader(self.data)

        # offset locations
        self.num_party_members = 0x20
        self.first_name_offset = 0x64
        self.entry_size = 0x2FC

        reader.seek(self.num_party_members)
        self.party_count = reader.read_u8()
        print(f"party count: {self.party_count}")

        # create a list of party members to iterate over easier
        self.party_members = []

        # we always have at least one party member
        reader.seek(self.first_name_offset)
        name = reader.read_cstring()

        self.party_members.append(name)

        # iterate over party members
        for i in range(1, self.party_count):
            offset = self.first_name_offset + (i * self.entry_size)
            reader.seek(offset)
            name = reader.read_cstring()

            if name:
                self.party_members.append(name)

        # protection: make sure we didn't add blank strings somehow.
        self.party_members = [m for m in self.party_members if m]

        print(self.party_members)

        self.modified_data = None

    def __pad_name(self, name: str):
        max_buffer_size = 18
        name_length = len(name.encode('utf-8'))
        difference = max_buffer_size - name_length

        return name + ("\x00" * difference)

    def build(self) -> bytes:
        self.modified_data = self.data
        # this packet has loads of data, but we only care about replacing
        # the party member names. they are at fixed offsets within the
        # packet, so we just jump straight to them and replace them.
        for member in self.party_members:
            self.modified_data = self.modified_data.replace(
                # "セラニー".encode(),
                # b"Serany\x00\x00\x00\x00\x00\x00")
                self.__pad_name(member).encode('utf-8'),
                self.__pad_name("Serany").encode('utf-8'))
