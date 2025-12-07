import ctypes


class MemWriterLocal:
    """Class to perform local memory functions."""

    def read_string(self, address: int) -> str:
        """Reads a null-terminated encoded string at address and returns a
        decoded utf-8 string.

        :address: Address to read.
        """
        string = ctypes.string_at(address)

        return string.decode('utf-8')


    def read_uint32(self, address: int, value: bool = False) -> ctypes.c_uint32 | int:
        """Reads a 32-bit uint at address and returns its value.

        :address: Address to read. :value: Whether to return the result
        as an int (True) or ctype (False).
        """
        result = ctypes.c_uint32.from_address(address)

        if value:
            return result.value

        return result


    def read_ulong32(self, address: int, value: bool = False) -> ctypes.c_ulong | int:
        """Reads a 32-bit ulong at address and returns its value.

        :address: Address to read. :value: Whether to return the result
        as an int (True) or ctype (False).
        """
        result = ctypes.c_ulong.from_address(address)

        if value:
            return result.value

        return result


    def read_bytes(self, address: int, length: int) -> bytes:
        """Reads length number of bytes at address and returns the bytes read.

        :address: Address to read. :length: Number of bytes to read.
        """
        buf = (ctypes.c_ubyte * length)
        data = buf.from_address(address)

        return bytes(data)


    def write_string(self, address: int, text: str) -> None:
        """Writes a null-terminated string at address.

        :address: Address to write to. :text: Text to write to address.
        """
        data = text.encode('utf-8') + b"\x00"
        return ctypes.memmove(address, data, len(data))
