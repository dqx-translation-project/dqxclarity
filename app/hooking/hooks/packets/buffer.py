import struct


class PacketReader:
    """A sequential reader for binary packet data."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_bytes(self, size: int) -> bytes:
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def read_u8(self) -> int:
        return struct.unpack('<B', self.read_bytes(1))[0]

    def read_u16(self) -> int:
        return struct.unpack('<H', self.read_bytes(2))[0]

    def read_u32(self) -> int:
        return struct.unpack('<I', self.read_bytes(4))[0]

    def read_u64(self) -> int:
        return struct.unpack('<Q', self.read_bytes(8))[0]

    def read_cstring(self, encoding: str = 'utf-8') -> str:
        """Read a null-terminated string."""
        end = self.data.find(b'\x00', self.pos)
        if end == -1:
            end = len(self.data)
        result = self.data[self.pos:end].decode(encoding)
        self.pos = end + 1  # skip past null terminator
        return result

    def seek(self, pos: int):
        self.pos = pos

    def skip(self, size: int):
        self.pos += size

    def remaining(self) -> bytes:
        return self.data[self.pos:]

    def remaining_size(self) -> int:
        return len(self.data) - self.pos

    def at_end(self) -> bool:
        return self.pos >= len(self.data)


class PacketWriter:
    """A sequential writer for constructing binary packets."""

    def __init__(self):
        self.data = bytearray()

    def write_bytes(self, data: bytes):
        self.data.extend(data)

    def write_u8(self, value: int):
        self.data.extend(struct.pack('<B', value))

    def write_u16(self, value: int):
        self.data.extend(struct.pack('<H', value))

    def write_u32(self, value: int):
        self.data.extend(struct.pack('<I', value))

    def write_u64(self, value: int):
        self.data.extend(struct.pack('<Q', value))

    def write_cstring(self, value: str, encoding: str = 'utf-8'):
        self.data.extend(value.encode(encoding))
        self.data.append(0)

    def build(self) -> bytes:
        return bytes(self.data)
