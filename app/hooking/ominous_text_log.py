from common.lib import get_project_root, setup_logger
from common.memory import MemWriter
from json import dumps

import os
import sys


class OminousLog:

    writer = None

    # all text is already translated as it's referencing the game files.
    def __init__(self, text_address: int):
        if not OminousLog.writer:
            OminousLog.writer = MemWriter()

        self.text_address = OminousLog.writer.unpack_to_int(text_address)
        self.text = OminousLog.writer.read_string(self.text_address)

        custom_text_logger = setup_logger("text_logger", get_project_root("logs/cutscene_text.log"))
        custom_text_logger.info(f"[Unknown Voice]:\n  => {self.text}\n")
        custom_text_logger.handlers[0].close()


def ominous_text_log_shellcode(esi_address: int) -> str:
    """Returns shellcode for ominous text logging hook.

    :param esi_address: Dialogue text.
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
    from hooking.ominous_text_log import OminousLog
    OminousLog({esi_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return shellcode
