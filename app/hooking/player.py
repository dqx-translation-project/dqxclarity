from common.lib import get_abs_path
from common.memory import read_bytes, read_string, unpack_to_int
from json import dumps

import os
import sqlite3
import sys


class GetPlayer:

    def __init__(self, address, debug=False):
        if debug:
            self.address = address
        else:
            self.address = unpack_to_int(address)

        player = read_string(self.address + 24)
        sibling = read_string(self.address + 96)
        sibling_relationship = self.__determine_sibling_relationship()

        self.__write_db(
            player_name=player,
            sibling_name=sibling,
            sibling_relationship=sibling_relationship
        )

    def __determine_sibling_relationship(self):
        check_byte = read_bytes(self.address + 96 + 19, size=1)
        if check_byte == b"\x01":
            return "older_brother"
        if check_byte == b"\x02":
            return "younger_brother"
        if check_byte == b"\x03":
            return "older_sister"
        if check_byte == b"\x04":
            return "younger_sister"


    def __write_db(self, player_name: str, sibling_name: str, sibling_relationship: str):
        db_file = "/".join([get_abs_path(__file__), "../misc_files/clarity_dialog.db"])

        query = f"""
        BEGIN TRANSACTION;
        DELETE FROM player;
        INSERT INTO player (type, name) VALUES
            ('player', '{player_name}'),
            ('sibling', '{sibling_name}'),
            ('sibling_relationship', '{sibling_relationship}');
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

# 115 bytes - <kyodai_rel*> byte
# 01 - older brother
#     <kyodai_rel1>: 兄ちゃん
#     <kyodai_rel2>: お兄ちゃん
#     <kyodai_rel3>: 兄
# 02 - younger brother
#     <kyodai_rel1>: 弟
#     <kyodai_rel2>: 弟
#     <kyodai_rel3>: 弟
# 03 - older sister
#     <kyodai_rel1>: 姉ちゃん
#     <kyodai_rel2>: お姉ちゃん
#     <kyodai_rel3>: 姉
# 04 - younger sister
#     <kyodai_rel1>: 妹
#     <kyodai_rel2>: 妹
#     <kyodai_rel3>: 妹
