from common.errors import AddressOutOfRange, MemoryReadError, MemoryWriteError
from ctypes import byref, wintypes
from loguru import logger as log

import pymem
import pymem.process
import pymem.ressources
import pymem.ressources.structure
import struct
import traceback


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


    def pattern_scan(self, pattern: bytes, return_multiple=False, use_regex=False, module=None, all_protections: bool=False, data_only: bool=False):
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
                use_regex=use_regex,
                data_only=data_only
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

    def get_protection(self, address: int) -> int:
        """Gets page protection of an address.

        :param address: Address to get protection from.
        :returns: Constant of the current protection.
        """
        return pymem.memory.virtual_query(
            self.proc.process_handle, address=address
        ).Protect

    def set_protection(
        self,
        address: int,
        new_protection: int = 0x40,
        size: int = 0x10,
    ) -> bool:
        """Sets the page protection of an address. Defaults to
        READ_WRITE_EXECUTE (0x40).

        :param address: Address to set the protection.
        :param new_protection: Constant to set. See Microsoft docs for
            more info: https://learn.microsoft.com/en-
            us/windows/win32/Memory/memory-protection-constants
        :param size: Size of the region to set protection to.
        """
        old_protection = wintypes.DWORD()
        success = pymem.ressources.kernel32.VirtualProtectEx(
            self.proc.process_handle,
            address,
            size,
            new_protection,
            byref(old_protection),
        )

        if not success:
            raise Exception(f"Failed to set protection on {hex(address)}.")

        return True

    def get_hook_bytecode(self, hook_address: int):
        """Returns a formatted jump address for your hook."""
        return b"\xE9" + self.pack_to_int(hook_address)


    def inject_python(self):
        """Injects the Python interpreter into the process."""
        try:
            self.proc.inject_python_interpreter()
            if self.proc._python_injected:
                if self.proc.py_run_simple_string:
                    return self.proc.py_run_simple_string

            log.exception(f"Python dll failed to inject. Details:\n{self.proc.__dict__}")
            return False
        except Exception:
            log.exception(f"Python dll failed to inject. Error: \n{str(traceback.print_exc())}\nDetails:\n{self.proc.__dict__}")
            return False


    def close(self):
        """Closes the process."""
        return self.proc.close_process()
