from common.db_ops import generate_m00_dict
from common.lib import encode_to_utf8, get_project_root, setup_logger
from common.memory import MemWriter
from common.translate import detect_lang
from json import dumps

import os
import sys


class CornerText:

    misc_files = get_project_root("misc_files")
    custom_text_logger = setup_logger("text_logger", get_project_root("logs/corner_text.log"))
    writer = None
    data = None

    def __init__(self, text_address: int, debug=False):
        if not CornerText.writer:
            CornerText.writer = MemWriter()
        if debug:
            self.text_address = text_address
        else:
            self.text_address = CornerText.writer.unpack_to_int(text_address)

        if CornerText.data is None:
            CornerText.data = generate_m00_dict("'custom_corner_text'")

        text = CornerText.writer.read_string(self.text_address)

        if detect_lang(text):
            if text in CornerText.data:
                to_write = CornerText.data[text]
                if to_write != "":
                    CornerText.writer.write_string(self.text_address, to_write)
            else:
                CornerText.custom_text_logger.info(f"--\n>>corner_text ::\n{text}")


def corner_text_shellcode(eax_address: int) -> str:
    """Returns shellcode for the translate function hook.

    address: Where text can be modified to be fed to the screen
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
    from hooking.corner_text import CornerText
    CornerText({eax_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return encode_to_utf8(shellcode).decode()
