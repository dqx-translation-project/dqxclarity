import ctypes
import re
import struct
import pymem
import pymem.process
from pymem.pattern import pattern_scan_all, pattern_scan_module
import pymem.exception
from common.errors import (
    AddressOutOfRange,
    MemoryReadError,
    MemoryWriteError,
    FailedToReadAddress,
    message_box_fatal_error,
)
from common.signatures import text_pattern


# pylint: disable=inconsistent-return-statements
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


def read_int(address: int):
    """Return an int from an address."""
    return PYM_PROCESS.read_int(address)


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
    Writes a string to memory at the given address.
    """
    return PYM_PROCESS.write_string(address, text + "\x00")


# pylint: disable=inconsistent-return-statements,no-else-return
def pattern_scan(pattern: bytes, return_multiple=False, module=None):
    """
    Scan for a byte pattern.
    """
    if module is not None:
        return pattern_scan_module(
            handle=PYM_PROCESS.process_handle,
            pattern=pattern,
            return_multiple=return_multiple,
            module=pymem.process.module_from_name(PYM_PROCESS.process_handle, module),
        )
    else:
        return pattern_scan_all(handle=PYM_PROCESS.process_handle, pattern=pattern, return_multiple=return_multiple)


def scan_backwards(start_addr: int, pattern: bytes):
    """
    From start_addr, read bytes backwards until a pattern is found.
    Used primarily for finding the beginning of an adhoc file.
    """
    curr_addr = start_addr
    curr_bytes = bytes()
    segment_size = 120  # give us a buffer to read from
    segment_buffer_size = segment_size * 2  # prevent match from getting chopped off
    loop_count = 1
    while True:
        curr_segment = read_bytes(curr_addr, segment_size)
        curr_bytes = curr_segment + curr_bytes  # want the pattern to be read left to right, so prepending
        if len(curr_bytes) > segment_buffer_size:
            curr_bytes = curr_bytes[:-segment_size]  # keep our buffer reasonably sized
        if pattern in curr_bytes:  # found our match
            position = re.search(pattern, curr_bytes).span(0)
            return curr_addr + position[0]
        curr_addr -= segment_size
        loop_count += 1
        if loop_count * segment_size > 1000000:
            return False  # this scan is slow, so don't scan forever.


def find_first_match(start_addr: int, pattern: bytes) -> int:
    """
    This is so dumb that this has to exist, but scan_pattern_page does not
    find patterns consistently, so we must read this byte by byte
    until we find a match. This works like scan backwards, but the other way around.
    """
    curr_addr = start_addr
    curr_bytes = bytes()
    segment_size = 120  # give us a buffer to read from
    segment_buffer_size = segment_size * 2  # prevent match from getting chopped off
    loop_count = 1
    while True:
        curr_segment = read_bytes(curr_addr, segment_size)
        curr_bytes = curr_segment + curr_bytes
        if pattern in curr_bytes:  # found our match
            position = re.search(pattern, curr_bytes).span(0)
            return curr_addr + position[0]
        if len(curr_bytes) > segment_buffer_size:
            curr_bytes = curr_bytes[segment_size:]  # keep our buffer reasonably sized
        curr_addr += segment_size
        loop_count += 1
        if loop_count * segment_size > 1000000:
            return False  # this scan is slow, so don't scan forever.


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


def get_start_of_game_text(indx_address: int) -> int:
    """
    Returns the address of the first character of text from a loaded
    game file. This should be used when starting at an INDX address.
    """
    # pylint: disable=pointless-statement
    address = find_first_match(indx_address, text_pattern)
    loop_count = 1
    if address:
        address += 16  # skip passed all the junk bytes
        while True:  # skip passed the padded 00's
            result = read_bytes(address, 1)
            if result != b"\x00":
                address
                break
            address += 1
            loop_count += 1
            if loop_count > 50:
                return False

        return address
    return None


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


def unpack_address_to_int(address: int):
    """
    Reads the first four bytes of memory and unpacks it into an address.
    """
    value = read_bytes(address, 4)

    return struct.unpack("<i", value)[0]


PYM_PROCESS = dqx_mem()
