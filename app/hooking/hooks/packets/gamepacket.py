import struct
from hooking.hooks.packets.datapacketrouter import DataPacketRouter
from loguru import logger as log


class GamePacket:
    """
    Defines a game packet that comes through this hook. Data packets are constructed
    of multiple segments and must be read by first determining the type of packet,
    reading in the correct number of payload bytes, while still making sure the
    remainder of the packet is appended to any modifications.
    """

    def __init__(self, raw: bytes):
        self.raw = raw
        self.outer = None
        self.size = None
        self.type = None
        self.payload = None
        self.data_type = None
        self.size_identifier = None
        self.modified_data = None

        # need to expose the original size to the original function for the return value.
        self.original_size = None

        # any bytes remaining in the packet, but not part of the current payload to process.
        self.remainder = None

        # first byte determines:
        #   - the type of the packet
        #       - it takes the upper 4 bits of the first byte for determination
        packet_type = struct.unpack("<B", self.raw[:1])[0] >> 4

        match packet_type:
            case 0:  # data packet. all actual game stuff is data. byte: 0x0X
                self.type = "data"
                return self.__recv_data()

            case 1:  # ping request. responds with pong. fixed at 9 bytes. byte: 0x1X
                self.type = "ping"
                self.size = len(self.raw)
                self.payload = self.raw[1:]

                if len(self.payload) != 8:
                    log.debug("[PING?] Met PING requirement, but did not contain 8 bytes in payload.")
                    return None
                return self.__recv_ping()

            case 2:  # pong request. calculates and stores RTT (round-trip time) at this+0x28. fixed at 9 bytes. byte: 0x2X
                self.type = "pong"
                self.size = len(self.raw)
                self.payload = self.raw[1:]

                if len(self.payload) != 8:
                    log.debug("[PONG?] Met PONG requirement, but did not contain 8 bytes in payload.")
                    return None
                return self.__recv_pong()

            case 3:  # acknowledgement. passes fixed 4-byte value to vtable+0x64. byte: 0x3X
                self.type = "ackn"
                return self.__recv_ackn()

    def __recv_ping(self) -> str:
        payload = struct.unpack("<Q", self.raw[1:])[0]

        # payload == milliseconds since last server restart?
        log.trace(f"[PING] {payload} milliseconds since last server restart.")

    def __recv_pong(self) -> str:
        payload = struct.unpack("<Q", self.raw[1:])[0]

        # some type of timing that is synchronized between the ping response using
        # `this` context. local time is stored at this+0x48, then this number is subtracted
        # from the pong, then stored as RTT at this+0x28.
        log.trace(f"[PONG] {payload}")

    def __recv_ackn(self) -> str:
        log.trace("[ACKN] Not implemented.")

    def __recv_data(self):
        """
        Reads the next segment in a packet stream.

        'remainder' is anything left in the stream.
        This is appended to our packet to keep the original packet intact.

        'original_size' is the return value we send back to frida. although
        the game will potentially read in our resized buffer, we don't update
        the stack context with our buffer, so we need the original code to know
        where it left off in the stream.
        """
        # first byte determines how to read the payload size.
        self.size_identifier = struct.unpack("<B", self.raw[:1])[0]

        match self.size_identifier:
            case 0:
                self.size = struct.unpack("<B", self.raw[1:2])[0]
                self.original_size = self.size + len(self.raw[0:2])
                self.payload = self.raw[2 : 2 + self.size]
                self.remainder = self.raw[2 + self.size :]
            case 1:
                self.size = struct.unpack("<H", self.raw[1:3])[0]
                self.original_size = self.size + len(self.raw[0:3])
                self.payload = self.raw[3 : 3 + self.size]
                self.remainder = self.raw[3 + self.size :]
            case 2:
                self.size = struct.unpack("<I", self.raw[1:5])[0]
                self.original_size = self.size + len(self.raw[0:4])
                self.payload = self.raw[5 : 5 + self.size]  # might be right? could be 4, haven't seen.
                self.remainder = self.raw[5 + self.size :]
            case 3:
                self.size = struct.unpack("<I", self.raw[1:5])[0]
                self.original_size = self.size + len(self.raw[0:4])
                self.payload = self.raw[5 : 5 + self.size]
                self.remainder = self.raw[5 + self.size :]

    def __recalculate_size(self, size: int) -> bytes:
        """Recalculate size of payload. Returns correct size based on identifier."""
        if size <= 0xFF:
            return b"\x00" + struct.pack("<B", size)
        elif size > 0xFF and size <= 0xFFFF:
            return b"\x01" + struct.pack("<H", size)
        elif size > 0xFFFF and size <= 0xFFFFFF:
            return b"\x02" + struct.pack("<I", size)
        elif size > 0xFFFFFF:
            return b"\x03" + struct.pack("<I", size)

    def hexdump(self, data: bytes, bytes_per_line: int = 16) -> str:
        """Format bytes as a hex dump with offset, hex, and ASCII columns.

        Args:
            data: Bytes to format.
            bytes_per_line: Number of bytes per line.

        Returns:
            Formatted hex dump string.
        """
        lines = []
        for offset in range(0, len(data), bytes_per_line):
            chunk = data[offset : offset + bytes_per_line]

            # hex column
            hex_parts = [f"{b:02X}" for b in chunk]
            hex_str = " ".join(hex_parts).ljust(bytes_per_line * 3 - 1)

            # ascii column
            ascii_str = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)

            lines.append(f"{offset:08X}  {hex_str}  |{ascii_str}|")

        return "\n".join(lines)

    def parse_data(self) -> bytes:
        if self.type == "data":
            if not self.payload:
                log.warning("[DATA] Could not determine payload.")
                return

            # have seen numerous times where the size of the packet does not
            # actually match the size of the payload. this does happen in
            # tcp networking, but it seems like it happens wayyy too much
            # in this game. perhaps the whole jp -> across the globe transit?
            if self.size != len(self.payload):
                log.warning("[DATA] Received payload invalid! Will not process.")
                return

            # if "ミナルバ".encode() in self.payload:
            #     log.info(self.hexdump(self.payload))

            router = DataPacketRouter(self.payload)
            router.parse()

            if router.modified_data and router.modified_size:
                self.modified_data = self.__recalculate_size(router.modified_size) + router.modified_data + self.remainder
