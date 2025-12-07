from common.db_ops import generate_m00_dict
from common.lib import get_project_root, setup_logger
from common.memory_local import MemWriterLocal
from common.translate import detect_lang
from json import dumps

import os
import sys


class CornerText:
    custom_text_logger = setup_logger(
        "text_logger", get_project_root("logs/corner_text.log")
    )
    data = None

    def __init__(self, text_address: int):
        if CornerText.data is None:
            CornerText.data = generate_m00_dict("'custom_corner_text'")

        writer = MemWriterLocal()
        text_address = writer.read_uint32(address=text_address, value=True)

        text = writer.read_string(address=text_address)

        if detect_lang(text):
            if text in CornerText.data:
                to_write = CornerText.data[text]
                if to_write != "":
                    writer.write_string(address=text_address, text=text)
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

    return shellcode
