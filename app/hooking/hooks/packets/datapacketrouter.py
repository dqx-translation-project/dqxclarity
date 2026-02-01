from hooking.hooks.packets.types.comm_window_list import CommWindowListPacket
from hooking.hooks.packets.types.entity import EntityPacket
from hooking.hooks.packets.types.master_quest import MasterQuestPacket
from hooking.hooks.packets.types.memory_list_main import MemoryListMainPacket
from hooking.hooks.packets.types.mytown_amenity import MyTownAmenityPacket
from hooking.hooks.packets.types.npc_dialogue import NpcDialoguePacket
from hooking.hooks.packets.types.party_list import PartyListPacket
from hooking.hooks.packets.types.quest import QuestPacket
from hooking.hooks.packets.types.server_list import ServerListPacket
from hooking.hooks.packets.types.storysofar import StorySoFarTextPacket
from hooking.hooks.packets.types.team_quest import TeamQuestPacket
from hooking.hooks.packets.types.walkthrough import WalkthroughPacket
from hooking.hooks.packets.types.weekly_request import WeeklyRequestPacket
from loguru import logger as log


def hexdump(data: bytes, bytes_per_line: int = 16) -> str:
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


class DataPacketRouter:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.op_code = raw[:1]
        self.marker = raw[1:3]
        self.data = raw[3:]

        self.modified_data = None
        self.modified_size = None

    def parse(self):
        packet = None

        if self.op_code == b"\x21":
            if self.marker == b"\xE5\x35":
                log.debug("[DATA] story_so_far window opened.")

            elif self.marker == b"\xBE\x01":
                log.debug("[DATA] story_so_far text found.")
                packet = StorySoFarTextPacket(self.data)

            elif self.marker == b"\xA8\x3C":
                log.debug("[DATA] npc dialogue visible.")
                packet = NpcDialoguePacket(self.data)

            elif self.marker == b"\x6D\xD4":
                log.debug("[DATA] walkthrough text visible.")
                packet = WalkthroughPacket(self.data)

        elif self.op_code == b"\x5D":
            if self.marker == b"\x2B\x15" or self.marker == b"\xCC\x51":
                log.debug("[DATA] quest text window opened.")
                packet = QuestPacket(self.data)

        elif self.op_code == b"\x87":
            if self.marker == b"\x54\x08" or self.marker == b"\x84\x08":
                log.debug("[DATA] server list.")
                packet = ServerListPacket(self.data)

            if self.marker == b"\x61\x85":
                log.debug("[DATA] important notice message.")

        elif self.op_code == b"\x0D":
            if self.marker == b"\x9E\xE1":
                log.debug("[DATA] team list.")
                packet = CommWindowListPacket(self.data)

            if self.marker == b"\xEE\x25":
                log.debug("[DATA] party message.")

            if self.marker == b"\x27\x11":
                log.debug("[DATA] team message.")

            if self.marker == b"\x76\x90":
                log.debug("[DATA] private message.")

            if self.marker == b"\x75\x5D":
                log.debug("[DATA] room message.")

        elif self.op_code == b"\x3D":
            if self.marker == b"\x16\xB6":
                log.debug("[DATA] team quest.")
                packet = TeamQuestPacket(self.data)

        elif self.op_code == b"\x52":
            if self.marker == b"\xEE\x25": # noqa: SIM102
                log.warning(f"[DATA] entity found.\n{hexdump(self.raw)}")
                packet = EntityPacket(self.data)

        elif self.op_code == b"\x66":
            if self.marker == b"\x4C\xC2":
                log.debug("[DATA] memory main list.")
                packet = MemoryListMainPacket(self.data)

            elif self.marker == b"\xDA\x30":
                log.debug("[DATA] memory chapter list.")
            elif self.marker == b"\x45\x69":
                log.debug("[DATA] memory sub chapter list.")

        elif self.op_code == b"\x79":
            if self.marker == b"\x99\x4B":
                log.debug("[DATA] master quest window opened.")
                packet = MasterQuestPacket(self.data)

        elif self.op_code == b"\x03":
            if self.marker == b"\xF7\xF5": #or self.marker == b"\x54\x08":
                log.debug("[DATA] party list.")
                packet = PartyListPacket(self.data)

        elif self.op_code == b"\x46":
            if self.marker == b"\x6B\xB8":
                log.debug("weekly request window open.")
                packet = WeeklyRequestPacket(self.data)

        elif self.op_code == b"\x4B":
            if self.marker == b"\x45\x69":
                log.debug("[DATA] mytown amenity name")
                packet = MyTownAmenityPacket(self.data)

        elif self.op_code == b"\x05":  # noqa: SIM102
            if self.marker == b"\xEA\x73":
                log.debug(f"[DATA] concierge name\n{hexdump(self.raw)}")

        if packet:
            packet.build()
            if packet.modified_data:
                self.modified_data = self.op_code + self.marker + packet.modified_data
                self.modified_size = len(self.modified_data)
                log.info(f"[DATA] Packet was modified!\n{hexdump(self.modified_data)}")
