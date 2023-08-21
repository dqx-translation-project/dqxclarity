from common.lib import get_abs_path, setup_logger
from common.memory import read_string, unpack_to_int, write_string
from common.translate import (
    clean_up_and_return_items,
    detect_lang,
    sqlite_read,
    sqlite_write,
    Translate,
)
from json import dumps, loads

import re
import sys
import textwrap


class Quest:

    misc_files = "/".join([get_abs_path(__file__), "../misc_files"])
    logger = setup_logger("out", "/".join([get_abs_path(__file__), "../out.log"]))
    quests = None

    def __init__(self, address, debug=False):
        if debug:
            self.address = address
        else:
            self.address = unpack_to_int(address)

        self.subquest_name_address = self.address + 20
        self.quest_name_address = self.address + 76
        self.quest_desc_address = self.address + 132
        self.quest_rewards_address = self.address + 640
        self.quest_repeat_rewards_address = self.address + 744

        self.subquest_name = read_string(self.subquest_name_address)
        self.quest_name = read_string(self.quest_name_address)
        self.quest_desc = read_string(self.quest_desc_address)
        self.quest_rewards = read_string(self.quest_rewards_address)
        self.quest_repeat_rewards = read_string(self.quest_repeat_rewards_address)

        self.is_ja = self.__is_ja()

        if Quest.quests is None:
            Quest.quests = self.__read_file(f"{Quest.misc_files}/eventTextSysQuestaClient.json")

        self.write_to_game()
        Quest.logger.info(f"Wrote to quest address: {self.address}")


    def __is_ja(self):
        return detect_lang(self.quest_desc)


    def __write_subquest_name(self):
        if self.is_ja:
            if data := self.__query_quest(self.subquest_name):
                write_string(address=self.subquest_name_address, text=data)


    def __write_quest_name(self):
        if self.is_ja:
            if data := self.__query_quest(self.quest_name):
                write_string(address=self.quest_name_address, text=data)


    def __write_quest_desc(self):
        if self.is_ja:
            if data := self.__translate_quest_desc():
                write_string(address=self.quest_desc_address, text=data)


    def __write_quest_rewards(self):
        if self.is_ja:
            if data := clean_up_and_return_items(self.quest_rewards):
                write_string(address=self.quest_rewards_address, text=data)


    def __write_repeat_quest_rewards(self):
        if self.is_ja:
            if data := clean_up_and_return_items(self.quest_repeat_rewards):
                write_string(address=self.quest_repeat_rewards_address, text=data)


    def __translate_quest_desc(self):
        translator = Translate()
        if db_quest_text := sqlite_read(
            text_to_query=self.quest_desc,
            language=Translate.region_code,
            table="quests"
        ):
            return db_quest_text

        full_text = re.sub("\n", " ", self.quest_desc)
        if translation := translator.translate(full_text):
            formatted_translation = textwrap.fill(translation, width=45, replace_whitespace=False)
            sqlite_write(
                source_text=self.quest_desc,
                table="quests",
                translated_text=formatted_translation,
                language=Translate.region_code
            )
            return formatted_translation
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


def quest_text_shellcode(eax_address: int, debug: bool) -> str:
    """Returns shellcode for the translate function hook.

    eax_address: Where text can be modified to be fed to the screen
    """
    import os
    local_paths = dumps(sys.path).replace("\\", "\\\\")
    log_path = os.path.join(os.path.abspath('.'), 'out.log').replace("\\", "\\\\")

    # Overwriting the process's sys.path with the one outside of the process
    # is required to run our imports and function code. It's also necessary to
    # escape the slashes.
    shellcode = f"""
try:
    import sys
    sys.path = {local_paths}
    from hooking.quest import Quest
    Quest({eax_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(e))
    """

    return str(shellcode)
