from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class WalkthroughPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.num_times_opened = reader.read_u32()
        self.padding = reader.read_bytes(4)
        self.text = reader.read_cstring()

        # fixed 277 byte buffer. remove a byte for null-termination
        # as reader seeks forward once on c-strings.
        padded_buffer_length = 276 - len(self.text.encode('utf-8'))
        self.text_padding = reader.read_bytes(padded_buffer_length)

        self.unknown_1 = reader.read_u32()
        self.padding = reader.read_bytes(4)
        self.remaining = reader.remaining()

        self.modified_text = None
        self.modified_data = None

    def build(self) -> bytes:
        writer = PacketWriter()

        # would replace with code that translates text.
        self.modified_text = self.text.replace("プクレットの村の", "qweaasdqweasdqweasdqwesdqweasdqweasdqweasd")  # test that text replace works.
        text = self.modified_text if self.modified_text is not None else self.text

        writer.write_u32(self.num_times_opened)
        writer.write_bytes(b'\x00' * 4)
        writer.write_cstring(text)

        # pad string up to fixed buffer amount
        padded_buffer_length = 276 - len(text.encode('utf-8'))
        writer.write_bytes(b'\x00' * padded_buffer_length)

        writer.write_u32(self.unknown_1)
        writer.write_bytes(b'\x00' * 4)
        writer.write_bytes(self.remaining)

        self.modified_data = writer.build()
