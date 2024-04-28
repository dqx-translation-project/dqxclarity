from common.errors import AddressOutOfRange, MemoryReadError, MemoryWriteError

import pymem
import pymem.exception
import pymem.process
import struct


class MemWriter:
    def __init__(self, process_name: str = "DQXGame.exe"):
        self.proc = self.attach(process_name)


    def attach(self, process_name: str = "DQXGame.exe"):
        proc = pymem.Pymem(process_name)
        # obscure issue seen on Windows 11 getting an OverflowError
        # https://github.com/srounet/Pymem/issues/19
        proc.process_handle &= 0xFFFFFFFF

        return proc


    def read_bytes(self, address: int, size: int):
        """Read n number of bytes at address.

        Args:
            address: The address to start at
            bytes_to_read: Number of bytes to read from start of address
        """
        if not 0 < address <= 0x7FFFFFFF:
            raise AddressOutOfRange(address)

        try:
            return self.proc.read_bytes(address, size)
        except Exception as e:
            raise MemoryReadError(address) from e


    def write_bytes(self, address: int, value: bytes):
        """Write bytes to memory at address.

        Args:
            address: The address to write to
            value: The bytes to write
        """
        size = len(value)

        try:
            self.proc.write_bytes(address, value, size)
        except Exception as e:
            raise MemoryWriteError(address) from e


    def read_string(self, address: int):
        """Reads a string from memory at the given address."""
        end_addr = address

        if end_addr is not None:
            while True:
                result = self.proc.read_bytes(end_addr, 1)
                end_addr = end_addr + 1
                if result == b"\x00":
                    bytes_to_read = end_addr - address
                    break

            return self.proc.read_string(address, bytes_to_read)
        return None


    def write_string(self, address: int, text: str):
        """Writes a null-terminated string to memory at the given address."""
        return self.proc.write_string(address, text + "\x00")


    def pattern_scan(self, pattern: bytes, return_multiple=False, use_regex=False, module=None, all_protections: bool = False):
        """Scan for a byte pattern."""
        if module is not None:
            return self.proc.pattern_scan_module(
                pattern=pattern,
                return_multiple=return_multiple,
                module=module
            )
        else:
            return self.proc.pattern_scan_all(
                pattern=pattern,
                all_protections=all_protections,
                return_multiple=return_multiple,
                use_regex=use_regex
            )

    def get_ptr_address(self, base: int, offsets: list):
        """Gets the address a pointer is pointing to.

        Args:
            base: Base of the pointer
            offsets: List of offsets
        """
        addr = self.proc.read_int(base)
        for offset in offsets:
            if offset != offsets[-1]:
                addr = self.proc.read_int(addr + offset)

        return addr + offsets[-1]


    def get_base_address(self, name: str ="DQXGame.exe") -> int:
        """Returns the base address of a module."""
        return pymem.process.module_from_name(self.proc.process_handle, name).lpBaseOfDll


    def pack_to_int(self, address: int) -> bytes:
        """Packs the address into little endian and returns the appropriate
        bytes."""
        return struct.pack("<i", address)


    def unpack_to_int(self, address: int):
        """Unpacks the address from little endian and returns the appropriate
        bytes."""
        value = self.read_bytes(address, 4)
        unpacked_address = struct.unpack("<i", value)

        return unpacked_address[0]


    def allocate_memory(self, size: int) -> int:
        """Allocates a defined number of bytes into the target process."""
        return self.proc.allocate(size)


    def calc_rel_addr(self, origin_address: int, destination_address: int) -> bytes:
        """Calculates the difference between addresses to return the relative
        offset."""

        # jmp forward
        if origin_address < destination_address:
            return bytes(self.pack_to_int(abs(origin_address - destination_address + 5)))

        # jmp backwards
        else:
            offset = -abs(origin_address - destination_address)
            unsigned_offset = offset + 2**32
            return unsigned_offset.to_bytes(4, "little")


    def get_hook_bytecode(self, hook_address: int):
        """Returns a formatted jump address for your hook."""
        return b"\xE9" + self.pack_to_int(hook_address)


    def close(self):
        """Closes the process."""
        return self.proc.close_process()
