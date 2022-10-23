from pathlib import Path
import random
from common.memory import unpack_to_int, read_bytes, write_bytes
from common.lib import query_csv, split_hex_into_spaces, generate_hex, write_file, dump_game_file
from common.blacklist import indx_blacklist


class EvtxFile:
    """
    Class for an Evtx file. See research/evtx_file_research.md
    for how this file is structured.
    """

    def __init__(self, evtx_address: int, write=True):
        self.evtx_address = evtx_address
        self.wrote = None
        self.file = None
        self.evtx = None
        self.indx_bytes = None

        if self.is_evtx():
            self.evtx = True
            self.indx_bytes = self.get_indx_bytes()
            if self.file_name():
                self.file = self.file_name()
                if write and not self.check_our_mark():
                    self.file_write()
                    self.leave_our_mark()
                    self.wrote = True

    def evtx_size(self) -> int:
        """Get size of EVTX section."""
        return unpack_to_int(self.evtx_address + 8)

    def is_evtx(self):
        """Check if this is a real EVTX file."""
        if read_bytes(self.evtx_address, 4).hex() == "45565458":  # EVTX:
            size = self.evtx_size()
            h_size = unpack_to_int(self.evtx_address + 4)
            if self.evtx_address + h_size + size < 0x7FFFFFFF:
                if read_bytes(self.evtx_address + h_size + size, 4).hex() == "464f4f54":  # FOOT
                    return True
        return False

    def cmnh_address(self):
        """Get address of CMNH header."""
        if self.is_evtx():
            address = self.evtx_address + 16
            if read_bytes(address, 4).hex() == "434d4e48":  # CMNH
                return address
        return False

    def blja_address(self):
        """Get address of BLJA header."""
        if address := self.cmnh_address():
            address = address + 48
            if read_bytes(address, 4).hex() == "424c4a41":  # BLJA
                return address
        return None

    def indx_address(self):
        """Get address of INDX header."""
        if address := self.blja_address():
            address = address + 16
            if read_bytes(address, 4).hex() == "494e4458":  # INDX
                return address
        return None

    def get_indx_bytes(self):
        """Get 128 bytes for hex_dict."""
        if address := self.indx_address():
            return read_bytes(address, 128)

    def indx_size(self):
        """Get size of INDX table."""
        if address := self.indx_address():
            return unpack_to_int(address + 8)
        return None

    def text_address(self):
        """Get address of TEXT header."""
        if indx_addr := self.indx_address():
            indx_size = self.indx_size()
            if read_bytes(indx_addr + 16 + indx_size, 4).hex() == "464f4f54":  # FOOT
                return indx_addr + 16 + indx_size + 16  # 16 bytes gets us out of the FOOT headers
        return None

    def text_size(self):
        """Get size of TEXT section."""
        if address := self.text_address():
            return unpack_to_int(address + 8)
        return None

    def string_start(self):
        """Get start of strings."""
        # Note: I didn't see a definitive way in the file, but
        # sometimes the strings start 16 bytes after TEXT and
        # sometimes at 18 bytes. We check for both here.
        if text_addr := self.text_address():
            start_addr = text_addr + 16
            if read_bytes(start_addr, 1).hex() != "00":
                return start_addr

            start_addr = text_addr + 18
            if read_bytes(start_addr, 1).hex() != "00":
                return start_addr

            print("Could not determine location of string_start.")
            return None
        return None

    def file_name(self):
        """Get filename of EVTX file from hex_dict."""
        if indx_addr := self.indx_address():
            indx_bytes = split_hex_into_spaces(str(read_bytes(indx_addr, 64).hex()))
            filename = query_csv(indx_bytes)
            if filename:
                return filename["file"]
        return None

    def file_write(self):
        """Write our JSON file over TEXT."""
        if address := self.string_start():
            if filename := self.file_name():
                en_hex = generate_hex(filename)
                if text_size := self.text_size():
                    if len(en_hex) <= text_size:
                        if not self.check_our_mark():
                            write_bytes(address, en_hex)
                            self.leave_our_mark()
                            return True
        return False

    def check_our_mark(self):
        """Check if we left our byte mark, indicating we already wrote to this EVTX file."""
        if address := self.indx_address():
            if read_bytes(address - 2, 1) == b"\x69":
                return True
        return False

    def leave_our_mark(self):
        """Write a byte mark in the EVTX file, indicating that we've written to this file."""
        if not self.check_our_mark():
            write_bytes(self.indx_address() - 2, b"\x69")
            return True
        return False

    def write_to_disk(self):
        """Write the EVTX file to disk."""
        if self.is_evtx():
            if self.indx_address():
                Path("unknown_json/en").mkdir(parents=True, exist_ok=True)
                Path("unknown_json/ja").mkdir(parents=True, exist_ok=True)
                hex_dict = "unknown_json/hex_dict.csv"
                csv_file = Path(hex_dict)

                indx_bytes = split_hex_into_spaces(str(read_bytes(self.indx_address(), 64).hex()))
                if indx_bytes in indx_blacklist:
                    return False

                if csv_file.is_file():
                    csv_result = query_csv(indx_bytes, hex_dict)
                    if csv_result:
                        return False
                else:
                    write_file("unknown_json", "hex_dict.csv", "a", "file,hex_string\n")

                start_addr = self.text_address() + 16
                end_addr = start_addr + self.text_size()
                file_size = end_addr - start_addr

                game_file = dump_game_file(start_addr, file_size)
                filename = str(random.randint(1, 1000000000)) + ".json"
                write_file("unknown_json", "hex_dict.csv", "a", f"json\_lang\en\{filename},{indx_bytes}\n")
                write_file("unknown_json/ja", filename, "w", game_file["ja"])
                write_file("unknown_json/en", filename, "w", game_file["en"])

                return True
