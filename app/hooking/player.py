from json import dumps
import os
import sqlite3
import sys
from common.lib import get_abs_path
from common.memory import unpack_to_int, read_string

class GetPlayer(object):

    def __init__(self, address, debug=False):
        if debug:
            self.address = address
        else:
            self.address = unpack_to_int(address)

        player = read_string(self.address + 24)
        sibling = read_string(self.address + 96)

        self.__write_db(player_name=player, sibling_name=sibling)


    def __write_db(self, player_name: str, sibling_name: str):
        db_file = "/".join([get_abs_path(__file__), "../misc_files/clarity_dialog.db"])

        query = f"""
        BEGIN TRANSACTION;
        DELETE FROM player;
        INSERT INTO player (type, name) VALUES
            ('player', '{player_name}'),
            ('sibling', '{sibling_name}');
        END TRANSACTION;
        """

        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.executescript(query)
        conn.commit()
        cursor.close()


def player_name_shellcode(eax_address: int) -> str:

    local_paths = dumps(sys.path).replace("\\", "\\\\")
    log_path = os.path.join(os.path.abspath('.'), 'logs\\console.log').replace("\\", "\\\\")

    shellcode = rf"""
try:
    import sys
    import traceback
    sys.path = {local_paths}
    from hooking.player import GetPlayer
    GetPlayer({eax_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return str(shellcode)
