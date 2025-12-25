from common.db_ops import generate_m00_dict
from common.memory_local import MemWriterLocal
from common.translate import transliterate_player_name
from json import dumps

import os
import re
import regex
import sys


class Nameplates:

    writer = MemWriterLocal()
    names = None
    jp_regex = regex.compile(r"\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Han}")

    def __init__(self, esp_address: int):
        if not Nameplates.names:
            # we override this a specific way --
            #   - default: monsters, npcs
            #   - any player name overrides
            #   - any mytown names
            # this is to make sure user customizations are captured
            monsters = generate_m00_dict(files="'monsters'")
            npcs = generate_m00_dict(files="'npcs', 'custom_npc_name_overrides'")
            players = generate_m00_dict(files="'local_player_names'")
            mytown = generate_m00_dict(files="'custom_concierge_mail_names', 'local_mytown_names'")

            Nameplates.names = {**monsters, **npcs, **players, **mytown}

        esp = Nameplates.writer.read_uint32(address=esp_address, value=True)
        arg_1 = Nameplates.writer.read_uint32(address=esp + 0x4, value=True)

        try:
            name = Nameplates.writer.read_string(address=arg_1)
        except OSError:  # eat access violation errors and return.
            return

        length = len(name.encode('utf-8'))

        if name:
            # if name isn't in japanese, return.
            if not self.__is_japanese(name):
                return

            result = Nameplates.names.get(name)

            if not result:
                result = transliterate_player_name(name)

            # take care not to write more than the original size of the string.
            Nameplates.writer.write_string(arg_1, "\x04" + result[: length - 1])

    def __is_japanese(cls, text: str):
        return bool(cls.jp_regex.search(text))

def nameplates_shellcode(esp_address: int) -> str:
    """Returns shellcode for the nameplates function hook.

    esp_address: Address of the nameplate name.
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
    from hooking.nameplates import Nameplates
    Nameplates({esp_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return shellcode
