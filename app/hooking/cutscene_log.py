from common.lib import get_project_root, setup_logger
from common.memory import MemWriter
from json import dumps

import os
import sys


class CutsceneLog:

    writer = None

    # all text is already translated as it's referencing the game files.
    def __init__(self, text_address: int, npc_address: int, debug=False):
        if not CutsceneLog.writer:
            CutsceneLog.writer = MemWriter()

        self.text_address = CutsceneLog.writer.unpack_to_int(text_address)
        self.npc_address = CutsceneLog.writer.unpack_to_int(npc_address)

        self.npc = CutsceneLog.writer.read_string(self.npc_address)
        self.text = CutsceneLog.writer.read_string(self.text_address + 0xb4) # 180

        custom_text_logger = setup_logger("text_logger", get_project_root("logs/cutscene_text.log"))
        custom_text_logger.info(f"[{self.npc}]:\n  => {self.text}\n")
        custom_text_logger.handlers[0].close()


def cutscene_log_shellcode(esp_address: int, esi_address: int) -> str:
    """Returns shellcode for the cutscene logging hook.

    :param esp_address: Dialogue text.
    :param esi_address: NPC name.
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
    from hooking.cutscene_log import CutsceneLog
    CutsceneLog({esp_address}, {esi_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return shellcode
