from common.db_ops import generate_m00_dict
from common.lib import get_project_root, setup_logger
from common.memory_local import MemWriterLocal
from json import dumps

import os
import regex
import sys


class MemChr:
    jp_regex = regex.compile(r"\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Han}")
    custom_text_logger = setup_logger(
        "memchr_logger", get_project_root("logs/memchr.log")
    )
    m00_text = None

    def __init__(self, esp_address: int):
        if not MemChr.m00_text:
            MemChr.m00_text = generate_m00_dict()

        writer = MemWriterLocal()

        # need to read the first argument on the stack (esp+4) to get the string to read.
        esp = writer.read_uint32(address=esp_address, value=True) + 0x4
        text_addr = writer.read_ulong32(address=esp, value=True)
        text = writer.read_string(address=text_addr)

        if not self.__is_japanese(text):
            return

        if text:
            found = MemChr.m00_text.get(text)
            if found:
                # the original strength length (in bytes) must be the exact same size as what we write,
                # or the game will throw an error code.
                orig_length = len(text.encode("utf-8"))
                found_length = len(found.encode("utf-8"))

                if found_length > orig_length:
                    found = found[:orig_length]
                elif found_length < orig_length:
                    # we pad the string with spaces to keep the size the same.
                    while len(found.encode("utf-8")) <= orig_length - 1:
                        found += " "

                writer.write_string(address=text_addr, text=found)
            else:
                MemChr.custom_text_logger.info(f"---\nUncaptured:\n{text}")

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
