from common.db_ops import generate_m00_dict
from common.lib import get_project_root, setup_logger
from common.memory import MemWriter
from json import dumps

import os
import regex
import sys


class MemChr:

    writer = None
    jp_regex = regex.compile(r"\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Han}")
    custom_text_logger = setup_logger("memchr_logger", get_project_root("logs/memchr.log"))
    m00_text = None

    def __init__(self, esp_address: int, debug=False):
        if not MemChr.writer:
            MemChr.writer = MemWriter()
        if not MemChr.m00_text:
            MemChr.m00_text = generate_m00_dict()

        if debug:
            self.esp_address = esp_address
        else:
            self.esp_address = MemChr.writer.unpack_to_int(esp_address)

        # need to read the first argument on the stack (esp+4) to get the string to read.
        self.text_address = MemChr.writer.proc.read_long(self.esp_address + 0x4)
        self.text = MemChr.writer.read_string(self.text_address)

        if not self.__is_japanese(self.text):
            return

        if self.text:
            found = MemChr.m00_text.get(self.text)
            if found:
                # the original strength length (in bytes) must be the exact same size as what we write,
                # or the game will throw an error code.
                orig_length = len(self.text.encode("utf-8"))
                found_length = len(found.encode("utf-8"))

                if found_length > orig_length:
                    found = found[:orig_length]
                elif found_length < orig_length:
                    # we pad the string with spaces to keep the size the same.
                    while len(found.encode("utf-8")) <= orig_length - 1:
                        found += " "

                MemChr.writer.write_string(address=self.text_address, text=found)
            else:
                MemChr.custom_text_logger.info(f"---\nUncaptured:\n{self.text}")

    def __is_japanese(cls, text: str):
        return bool(cls.jp_regex.search(text))


def memchr_shellcode(esp_address: int) -> str:
    """Returns shellcode for the memchr function hook.

    esp_address: Address of where to find value of esp.
    """
    local_paths = dumps(sys.path).replace("\\", "\\\\")
    log_path = os.path.join(os.path.abspath('.'), 'logs\\console.log').replace("\\", "\\\\")

    # Overwriting the process's sys.path with the one outside of the process
    # is required to run our imports and function code. It's also necessary to
    # escape the slashes.
    shellcode = f"""
try:
    import sys
    import traceback
    sys.path = {local_paths}
    from hooking.memchr import MemChr
    MemChr({esp_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return shellcode
