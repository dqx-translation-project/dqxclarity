from common.db_ops import generate_m00_dict, sql_read, sql_write
from common.lib import encode_to_utf8, get_project_root
from common.memory import MemWriter
from common.translate import clean_up_and_return_items, detect_lang, Translate
from json import dumps, loads

import os
import sys


class Quest:

    misc_files = get_project_root("misc_files")
    quests = None
    writer = None

    def __init__(self, address, debug=False):
        if not Quest.writer:
            Quest.writer = MemWriter()

        if debug:
            self.address = address
        else:
            self.address = Quest.writer.unpack_to_int(address)

        self.subquest_name_address = self.address + 20
        self.quest_name_address = self.address + 76
        self.quest_desc_address = self.address + 132
        self.quest_rewards_address = self.address + 640
        self.quest_repeat_rewards_address = self.address + 744

        self.subquest_name = Quest.writer.read_string(self.subquest_name_address)
        self.quest_name = Quest.writer.read_string(self.quest_name_address)
        self.quest_desc = Quest.writer.read_string(self.quest_desc_address)
        self.quest_rewards = Quest.writer.read_string(self.quest_rewards_address)
        self.quest_repeat_rewards = Quest.writer.read_string(self.quest_repeat_rewards_address)

        self.is_ja = self.__is_ja()

        if Quest.quests is None:
            Quest.quests = generate_m00_dict(files="'quests'")

        self.write_to_game()


    def __is_ja(self):
        return detect_lang(self.quest_desc)


    def __write_subquest_name(self):
        if self.is_ja:
            if data := self.__query_quest(self.subquest_name):
                Quest.writer.write_string(address=self.subquest_name_address, text=data)


    def __write_quest_name(self):
        if self.is_ja:
            if data := self.__query_quest(self.quest_name):
                Quest.writer.write_string(address=self.quest_name_address, text=data)


    def __write_quest_desc(self):
        if self.is_ja:
            if data := self.__translate_quest_desc():
                Quest.writer.write_string(address=self.quest_desc_address, text=data)


    def __write_quest_rewards(self):
        if self.is_ja:
            if data := clean_up_and_return_items(self.quest_rewards):
                Quest.writer.write_string(address=self.quest_rewards_address, text=data)


    def __write_repeat_quest_rewards(self):
        if self.is_ja:
            if data := clean_up_and_return_items(self.quest_repeat_rewards):
                Quest.writer.write_string(address=self.quest_repeat_rewards_address, text=data)


    def __translate_quest_desc(self):
        translator = Translate()
        if db_quest_text := sql_read(
            text=self.quest_desc,
            table="quests"
        ):
            return db_quest_text

        if translation := translator.sanitize_and_translate(
            self.quest_desc,
            wrap_width=49,
            max_lines=6,
            add_brs=False
        ):
            sql_write(
                source_text=self.quest_desc,
                translated_text=translation,
                table="quests"
            )
            return translation
        return None


    def __read_file(self, file):
        """Reads a json file and returns a single key, value dict."""
        with open(file, encoding="utf-8") as json_data:
            data = loads(json_data.read())
        new_dict = dict()
        for key in data:
            new_dict.update(data[key])
        return new_dict


    def __query_quest(self, text: str):
        if value := Quest.quests.get(text):
            return value
        return None


    def write_to_game(self):
        self.__write_subquest_name()
        self.__write_quest_name()
        self.__write_quest_desc()
        self.__write_quest_rewards()
        self.__write_repeat_quest_rewards()


def quest_text_shellcode(address: int) -> str:
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
    from hooking.quest import Quest
    Quest({address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return encode_to_utf8(shellcode).decode()
