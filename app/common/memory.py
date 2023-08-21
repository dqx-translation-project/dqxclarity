from common.errors import (
    AddressOutOfRange,
    FailedToReadAddress,
    MemoryReadError,
    MemoryWriteError,
    message_box_fatal_error,
)
from loguru import logger
from pymem.pattern import pattern_scan_all, pattern_scan_module

import pymem
import pymem.exception
import pymem.process
import struct
import sys


def dqx_mem():
    """
    Instantiates a pymem instance.
    """
    try:
        exe = pymem.Pymem("DQXGame.exe")
        # obscure issue seen on Windows 11 getting an OverflowError
        # https://github.com/srounet/Pymem/issues/19
        exe.process_handle &= 0xFFFFFFFF
        return exe
    except pymem.exception.ProcessNotFound:
        message_box_fatal_error("DQX not found", "Open DQX, get to the title screen and re-launch.")


def read_bytes(address: int, size: int):
    """
    Read n number of bytes at address.

    Args:
        address: The address to start at
        bytes_to_read: Number of bytes to read from start of address
    """
    if address is None:
        raise FailedToReadAddress(address)

    if not 0 < address <= 0x7FFFFFFF:
        raise AddressOutOfRange(address)

    try:
        return PYM_PROCESS.read_bytes(address, size)
    except Exception as e:
        raise MemoryReadError(address) from e


def write_bytes(address: int, value: bytes):
    """
    Write bytes to memory at address.

    Args:
        address: The address to write to
        value: The bytes to write
    """
    size = len(value)

    try:
        PYM_PROCESS.write_bytes(address, value, size)
    except Exception as e:
        raise MemoryWriteError(address) from e


def read_string(address: int):
    """
    Reads a string from memory at the given address.
    """
    end_addr = address

    if end_addr is not None:
        while True:
            result = PYM_PROCESS.read_bytes(end_addr, 1)
            end_addr = end_addr + 1
            if result == b"\x00":
                bytes_to_read = end_addr - address
                break

        return PYM_PROCESS.read_string(address, bytes_to_read)
    return None


def write_string(address: int, text: str):
    """
    Writes a null-terminated string to memory at the given address.
    """
    return PYM_PROCESS.write_string(address, text + "\x00")


def pattern_scan(pattern: bytes, return_multiple=False, use_regex=False, module=None):
    """
    Scan for a byte pattern.
    """
    try:
        if module is not None:
            return pattern_scan_module(
                handle=PYM_PROCESS.process_handle,
                pattern=pattern,
                return_multiple=return_multiple,
                module=pymem.process.module_from_name(PYM_PROCESS.process_handle, module),
                use_regex=use_regex
            )
        else:
            return pattern_scan_all(
                handle=PYM_PROCESS.process_handle,
                pattern=pattern,
                all_protections=False,
                return_multiple=return_multiple,
                use_regex=use_regex
            )
    except pymem.exception.WinAPIError as e:
        if e.error_code == 299:
            logger.debug("WinApi error 299: Impartial read. Ignoring.")
            return None
        elif e.error_code == 5:  # ERROR_ACCESS_DENIED. *usually* means the game client was closed
            logger.error(f"Cannot find DQXGame.exe process. dqxclarity will exit.")
            sys.exit(1)
        else:
            raise


def get_ptr_address(base, offsets):
    """
    Gets the address a pointer is pointing to.

    Args:
        base: Base of the pointer
        offsets: List of offsets
    """
    addr = PYM_PROCESS.read_int(base)
    for offset in offsets:
        if offset != offsets[-1]:
            addr = PYM_PROCESS.read_int(addr + offset)

    return addr + offsets[-1]


def get_base_address(name="DQXGame.exe") -> int:
    """
    Returns the base address of a module. Defaults to DQXGame.exe.
    """
    return pymem.process.module_from_name(PYM_PROCESS.process_handle, name).lpBaseOfDll


def pack_to_int(address: int) -> bytes:
    """
    Packs the address into little endian and returns the appropriate bytes.
    """
    return struct.pack("<i", address)


def unpack_to_int(address: int):
    """
    Unpacks the address from little endian and returns the appropriate bytes.
    """
    value = read_bytes(address, 4)
    unpacked_address = struct.unpack("<i", value)

    return unpacked_address[0]


def allocate_memory(size: int) -> int:
    """
    Allocates a defined number of bytes into the target process.
    """
    return PYM_PROCESS.allocate(size)


def calc_rel_addr(origin_address: int, destination_address: int) -> bytes:
    """
    Calculates the difference between addresses to return the relative offset.
    """

    # jmp forward
    if origin_address < destination_address:
        return bytes(pack_to_int(abs(origin_address - destination_address + 5)))

    # jmp backwards
    else:
        offset = -abs(origin_address - destination_address)
        unsigned_offset = offset + 2**32
        return unsigned_offset.to_bytes(4, "little")


def get_hook_bytecode(hook_address: int):
    """
    Returns a formatted jump address for your hook.
    """
    return b"\xE9" + pack_to_int(hook_address)


PYM_PROCESS = dqx_mem()
