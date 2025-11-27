from common.lib import get_project_root, setup_logger
from common.memory import MemWriter
from common.translate import detect_lang
from json import dumps

import os
import regex
import sys


class MemChr:

    writer = None
    jp_regex = regex.compile(r"\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Han}")
    custom_text_logger = setup_logger("memchr_logger", get_project_root("logs/memchr.log"))

    def __init__(self, esp_address: int, debug=False):
        if not MemChr.writer:
            MemChr.writer = MemWriter()
        if debug:
            self.esp_address = esp_address
        else:
            self.esp_address = MemChr.writer.unpack_to_int(esp_address)

        # need to read the first argument on the stack (esp+4) to get the string to read.
        self.text_address = MemChr.writer.proc.read_long(self.esp_address + 0x4)
        self.text = MemChr.writer.read_string(self.text_address)

        def is_japanese(s):
            return bool(MemChr.jp_regex.search(s))

        if not is_japanese(self.text):
            return

        MemChr.custom_text_logger.info(f"---\n{self.text}\n")


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
