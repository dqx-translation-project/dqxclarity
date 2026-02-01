from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class StorySoFarTextPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.num_times_opened = reader.read_u32()
        self.padding = reader.read_bytes(4)
        self.text = reader.read_cstring()

        # no idea what the rest of this is, but we don't have
        # to know either.
        self.remaining = reader.remaining()

        self.modified_text = None
        self.modified_data = None

    def build(self) -> bytes:
        # the original packet is fixed at 531 total bytes, including
        # the headers that are constructed outside of this function.
        # this gives us a maximum of a 517 byte string --
        # including the null terminator. what's interesting is that if you
        # look at the example packet at the top of this file, there is a lot
        # of extra junk that follows the string. none of this junk actually
        # gets read by the game; just the string itself. so, we end up just
        # throwing it all out so we can have more freedom with our text.
        # the game window won't even fit a 517 byte string, but it's there!
        # it is very important that the packet does not exceed 531 bytes,
        # or it'll crash.
        self.modified_text = self.text.replace("ていた　ア", "sdfgsdgasdfasdffwertgwetwergergdfgh")
        text = self.modified_text if self.modified_text is not None else self.text

        writer = PacketWriter()
        writer.write_u32(self.num_times_opened)
        writer.write_bytes(b'\x00' * 4)
        writer.write_cstring(text[:516])  # don't exceed the packet maximum.

        padding = 516 - len(text.encode('utf-8'))
        writer.write_bytes(b"\x00" * padding)

        self.modified_data = writer.build()
