from common.db_ops import sql_read, sql_write
from common.memory_local import MemWriterLocal
from common.translate import Translator
from json import dumps

import os
import regex
import sys


class Walkthrough:
    jp_regex = regex.compile(r"\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Han}")
    translator = Translator()
    writer = MemWriterLocal()

    def __init__(self, text_address: int):
        text_address = Walkthrough.writer.read_uint32(address=text_address, value=True)
        text = Walkthrough.writer.read_string(address=text_address)

        if not self.__is_japanese(text):
            return

        result = sql_read(text=text, table="walkthrough")

        if result:
            Walkthrough.writer.write_string(address=text_address, text=result)
        else:
            translated_text = Walkthrough.translator.translate(
                text=text, wrap_width=31, max_lines=3, add_brs=False
            )

            sql_write(
                source_text=text, translated_text=translated_text, table="walkthrough"
            )

            Walkthrough.writer.write_string(address=text_address, text=translated_text)

    def __is_japanese(cls, text: str):
        return bool(cls.jp_regex.search(text))


def walkthrough_shellcode(edi_address: int) -> str:
    """Returns shellcode for the translate function hook.

    address: Where text can be modified to be fed to the screen
    """
    local_paths = dumps(sys.path).replace("\\", "\\\\")
    log_path = os.path.join(os.path.abspath("."), "logs\\console.log").replace(
        "\\", "\\\\"
    )

    # Overwriting the process's sys.path with the one outside of the process
    # is required to run our imports and function code. It's also necessary to
    # escape the slashes.
    shellcode = f"""
try:
    import sys
    import traceback
    sys.path = {local_paths}
    from hooking.walkthrough import Walkthrough
    Walkthrough({edi_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return shellcode
