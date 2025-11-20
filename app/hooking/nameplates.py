from common.db_ops import generate_m00_dict
from common.memory import MemWriter
from common.translate import transliterate_player_name
from json import dumps

import os
import re
import sys


class Nameplates:

    writer = None
    names = None
    ja_pattern = re.compile(b"[\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xef]")

    def __init__(self, address):
        if not Nameplates.writer:
            Nameplates.writer = MemWriter()

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

        self.address = Nameplates.writer.unpack_to_int(address)
        self.prefix = Nameplates.writer.read_bytes(self.address, 1)

        # if byte doesn't start with a jp-encoded byte, dip out - it's not a name.
        if not Nameplates.ja_pattern.match(self.prefix):
            return

        self.name = Nameplates.writer.read_string(self.address)
        self.length = len(self.name.encode('utf-8'))

        if self.name:
            result = Nameplates.names.get(self.name)

            if not result:
                result = transliterate_player_name(self.name)

            # take care not to write more than the original size of the string.
            Nameplates.writer.write_string(self.address, "\x04" + result[:self.length])


def nameplates_shellcode(address: int) -> str:
    """Returns shellcode for the nameplates function hook.

    address: Address of the nameplate name.
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
    Nameplates({address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return shellcode
