from common.db_ops import sql_read
from common.lib import (
    encode_to_utf8,
    get_project_root,
    merge_jsons,
    setup_logger,
)
from common.memory import MemWriter
from common.translate import convert_into_eng, detect_lang
from glob import glob
from json import dumps

import os
import sys


class NetworkTextTranslate:

    misc_files = get_project_root("misc_files")
    custom_text_logger = setup_logger("text_logger", get_project_root("logs/custom_text.log"))
    m00_text = None
    writer = None

    translate = {
        "M_pc": "pc_name",
        "M_npc": "npc_name",
        "L_SENDER_NAME": "mail_name",
        "B_TARGET_RPL": "spell_target",
        "B_ACTOR": "pc_name",
        "B_TARGET": "pc_name",
        "M_00": "string",  # generic string of several types (walkthrough, team quests, mail)
        "M_kaisetubun": "story_so_far",
        "C_QUEST": "dracky_announcements_quest_complete",
        "C_PC": "dracky_announcements_player_name",
        "M_OWNER": "house_owner",
        "M_hiryu": "dragon_name",
        "L_HIRYU": "dragon_name",
        "L_HIRYU_NAME": "dragon_name",
        "M_name": "pc_name",
        "M_02": "menu_header",
        "M_header": "menu_header",
        "M_item": "mail_preview"
    }

    def __init__(self, text_address, var_address):
        if not NetworkTextTranslate.writer:
            NetworkTextTranslate.writer = MemWriter()
        self.text_address = NetworkTextTranslate.writer.unpack_to_int(text_address)
        self.var_address = NetworkTextTranslate.writer.unpack_to_int(var_address)

        if NetworkTextTranslate.m00_text is None:
            NetworkTextTranslate.m00_text = self.__get_m00_strings()

        category = NetworkTextTranslate.writer.read_string(self.var_address + 40)  # var name is 40 bytes in
        if category in NetworkTextTranslate.translate:
            if category == "B_TARGET_RPL":
                self_text = NetworkTextTranslate.writer.read_string(self.text_address)
                if self_text == "自分":
                    NetworkTextTranslate.writer.write_string(self.text_address, "self")
                return
            elif category in ["M_pc", "M_npc", "B_ACTOR", "B_TARGET", "C_PC", "L_SENDER_NAME", "M_OWNER", "M_hiryu", "L_HIRYU", "L_HIRYU_NAME", "M_name"]:  # npc or player names
                name = NetworkTextTranslate.writer.read_string(self.text_address)
                if name in NetworkTextTranslate.m00_text:
                    name_to_write = NetworkTextTranslate.m00_text[name]
                else:
                    name_to_write = convert_into_eng(name)
                NetworkTextTranslate.writer.write_string(self.text_address, name_to_write)
            elif category in ["M_00", "C_QUEST", "M_02", "M_header", "M_item"]:
                m00_string = NetworkTextTranslate.writer.read_string(self.text_address)
                if m00_string in NetworkTextTranslate.m00_text:
                    to_write = NetworkTextTranslate.m00_text[m00_string]
                    if to_write != "":
                        NetworkTextTranslate.writer.write_string(self.text_address, to_write)
                else:
                    NetworkTextTranslate.custom_text_logger.info(f"--\n>>m00_str ::\n{m00_string}")
            elif category == "M_kaisetubun":
                # this captures story so far AND monster trivia.
                # unfortunately, unsure of how to figure out which one is focused
                # on story_so_far, but if it isn't in the db, we will just log it.
                story_desc = NetworkTextTranslate.writer.read_string(self.text_address)
                if detect_lang(story_desc):
                    translated = self.__translate_story(story_desc)
                    if translated:
                        # we need to truncate the string if the length of the japanese
                        # string is shorter than the english string, or we'll write over
                        # game data and cause a crash.
                        story_desc_len = len(bytes(story_desc, encoding="utf-8"))
                        NetworkTextTranslate.writer.write_string(self.text_address, translated[:story_desc_len])
                    else:
                        NetworkTextTranslate.custom_text_logger.info(f"--\n{category} ::\n{story_desc}")
        else:
            NetworkTextTranslate.custom_text_logger.info(f"--\n{category} ::\n{NetworkTextTranslate.writer.read_string(self.text_address)}")
        return


    def __get_m00_strings(self):
        """Merges all jsons in the misc_files folder into one big dict."""
        json_files = glob(f"{NetworkTextTranslate.misc_files}/*.json")
        m00_strings = merge_jsons(json_files)

        return m00_strings


    def __translate_story(self, text: str):
        """Looks up text in the story_so_far table for story text. If found,
        returns the text.

        :param text: Text of the current page of the story.
        :returns: Translated text.
        """
        if story_text := sql_read(
            text=text,
            table="story_so_far",
            language="en",
        ):
            return story_text

        return None


def network_text_shellcode(ecx_address: int, esp_address) -> str:

    local_paths = dumps(sys.path).replace("\\", "\\\\")
    log_path = os.path.join(os.path.abspath('.'), 'logs\\console.log').replace("\\", "\\\\")

    shellcode = rf"""
try:
    import sys
    import traceback
    sys.path = {local_paths}
    from hooking.network_text import NetworkTextTranslate
    NetworkTextTranslate({ecx_address}, {esp_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return encode_to_utf8(shellcode).decode()
