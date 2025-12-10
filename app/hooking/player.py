"""This hook is triggered once the player has logged into the game with their
selected character.

It currently reads:
    - The player's name
    - The sibling's name
    - The relationship between player and sibling
It uses this information to update various data in the local database that replaces placeholder tags
related to the above read data. This makes it so that when the strings are encountered in game, they
exactly match when being looked up in database, returning a result.
"""

from common.db_ops import db_query, generate_m00_dict, init_db
from common.memory_local import MemWriterLocal
from common.translate import transliterate_player_name
from json import dumps

import os
import sys


class GetPlayer:
    writer = MemWriterLocal()
    player_names = None

    def __init__(self, address):
        if not GetPlayer.player_names:
            GetPlayer.player_names = generate_m00_dict(files="'local_player_names'")

        self.address = GetPlayer.writer.read_uint32(address=address, value=True)

        self.ja_player_name = GetPlayer.writer.read_string(address=self.address + 24)
        self.ja_sibling_name = GetPlayer.writer.read_string(address=self.address + 100)

        self.en_player_name = self.__get_en_player_name(name=self.ja_player_name)
        self.en_sibling_name = self.__get_en_player_name(name=self.ja_sibling_name)
        self.sibling_relationship = self.__determine_sibling_relationship()

        self.__write_player()
        self.__load_story_so_far_into_db()
        self.__load_fixed_dialog_into_db()
        self.__update_m00_table()

    def __determine_sibling_relationship(self):
        check_byte = GetPlayer.writer.read_bytes(
            address=self.address + 100 + 19, length=1
        )
        if check_byte == b"\x01":
            return "older_brother"
        if check_byte == b"\x02":
            return "younger_brother"
        if check_byte == b"\x03":
            return "older_sister"
        if check_byte == b"\x04":
            return "younger_sister"

    def __get_en_player_name(self, name: str):
        if result := GetPlayer.player_names.get(name):
            return result

        return transliterate_player_name(word=name)

    def __write_player(self):
        query = f"""
        BEGIN TRANSACTION;
        DELETE FROM player;
        INSERT INTO player (type, name) VALUES
            ('player', '{self.ja_player_name}'),
            ('sibling', '{self.ja_sibling_name}'),
            ('sibling_relationship', '{self.sibling_relationship}');
        END TRANSACTION;
        """

        try:
            conn, cursor = init_db()
            cursor.executescript(query)
            conn.commit()
        finally:
            conn.close()


    def __replace_with_en_names(self, string: str):
        new_string = string.replace("<pnplacehold>", self.en_player_name)
        new_string = new_string.replace("<snplacehold>", self.en_sibling_name)

        if self.sibling_relationship in ["older_brother", "younger_brother"]:
            new_string = new_string.replace("<kyodai_rel1>", "brother")
            new_string = new_string.replace("<kyodai_rel2>", "brother")
            new_string = new_string.replace("<kyodai_rel3>", "brother")
        elif self.sibling_relationship in ["older_sister", "younger_sister"]:
            new_string = new_string.replace("<kyodai_rel1>", "sister")
            new_string = new_string.replace("<kyodai_rel2>", "sister")
            new_string = new_string.replace("<kyodai_rel3>", "sister")

        return new_string


    def __replace_with_ja_names(self, string: str):
        new_string = string.replace("<pnplacehold>", self.ja_player_name)
        new_string = new_string.replace("<snplacehold>", self.ja_sibling_name)

        if self.sibling_relationship == "older_brother":
            new_string = new_string.replace("<kyodai_rel1>", "兄ちゃん")
            new_string = new_string.replace("<kyodai_rel2>", "お兄ちゃん")
            new_string = new_string.replace("<kyodai_rel3>", "兄")
        elif self.sibling_relationship == "younger_brother":
            new_string = new_string.replace("<kyodai_rel1>", "弟")
            new_string = new_string.replace("<kyodai_rel2>", "弟")
            new_string = new_string.replace("<kyodai_rel3>", "弟")
        elif self.sibling_relationship == "older_sister":
            new_string = new_string.replace("<kyodai_rel1>", "姉ちゃん")
            new_string = new_string.replace("<kyodai_rel2>", "お姉ちゃん")
            new_string = new_string.replace("<kyodai_rel3>", "姉")
        elif self.sibling_relationship == "younger_sister":
            new_string = new_string.replace("<kyodai_rel1>", "妹")
            new_string = new_string.replace("<kyodai_rel2>", "妹")
            new_string = new_string.replace("<kyodai_rel3>", "妹")

        return new_string


    def __load_story_so_far_into_db(self):
        conn, cursor = init_db()

        query = "DELETE FROM story_so_far"
        cursor.execute(query)

        query = "SELECT * FROM story_so_far_template"
        cursor.execute(query)

        results = cursor.fetchall()

        query_list = []
        for ja, en in results:
            fixed_ja = self.__replace_with_ja_names(ja.replace("'", "''"))
            fixed_en = self.__replace_with_en_names(en.replace("'", "''"))

            query_value = f"('{fixed_ja}', '{fixed_en}')"
            query_list.append(query_value)

        insert_values = ','.join(query_list)
        query = f"INSERT INTO story_so_far (ja, en) VALUES {insert_values};"
        cursor.execute(query)
        conn.commit()
        conn.close()


    def __load_fixed_dialog_into_db(self):
        conn, cursor = init_db()

        query = "DELETE FROM bad_strings"
        cursor.execute(query)

        query = "SELECT ja, en, bad_string FROM fixed_dialog_template"
        cursor.execute(query)

        results = cursor.fetchall()

        dialog_list = []
        bad_strings_list = []
        for ja, en, bad_string in results:
            fixed_ja = self.__replace_with_ja_names(ja.replace("'", "''"))
            fixed_en = self.__replace_with_en_names(en.replace("'", "''"))

            query_value = f"('{fixed_ja}', '{fixed_en}')"

            if bad_string == 0:
                dialog_list.append(query_value)
            elif bad_string == 1:
                bad_strings_list.append(query_value)

        dialog_values = ','.join(dialog_list)
        bad_string_values = ','.join(bad_strings_list)

        if len(dialog_values) > 0:
            query = f"INSERT OR REPLACE INTO dialog (ja, en) VALUES {dialog_values};"
            cursor.execute(query)
        if len(bad_string_values) > 0:
            query = f"INSERT OR REPLACE INTO bad_strings (ja, en) VALUES {bad_string_values};"
            cursor.execute(query)
        conn.commit()
        conn.close()


    def __update_m00_table(self):
        ja_query = f"""UPDATE m00_strings SET
            ja = replace(ja, '<pnplacehold>', '{self.ja_player_name}'),
            en = replace(en, '<pnplacehold>', '{self.en_player_name}')
        """
        en_query = f"""UPDATE m00_strings SET
            en = replace(en, '<snplacehold>', '{self.en_sibling_name}'),
            ja = replace(ja, '<snplacehold>', '{self.ja_sibling_name}')
        """

        db_query(ja_query)
        db_query(en_query)


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

    return shellcode
