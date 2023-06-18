from json import dumps
import os
import re
import sys
import textwrap
from common.lib import get_abs_path, setup_logger, merge_jsons
from common.memory import read_string, write_string, unpack_to_int, read_bytes
from common.translate import (
    Translate,
    sqlite_read,
    sqlite_write,
    convert_into_eng
)


class NetworkTextTranslate(object):

    misc_files = "/".join([get_abs_path(__file__), "../misc_files"])
    logger = setup_logger("out", "/".join([get_abs_path(__file__), "../out.log"]))
    npc_names = None

    translate = {
        "M_pc": "pc_name",
        "M_npc": "npc_name",
        "L_SENDER_NAME": "mail_name",
        "B_TARGET_RPL": "自分",
        "B_ACTOR": "pc_name",
        "B_TARGET": "pc_name",
        "M_00": "string",  # generic string of several types (walkthrough, team quests, mail)
        "M_kaisetubun": "story_so_far",
        "C_QUEST": "dracky_announcements_quest_complete",
        "C_PC": "dracky_announcements_player_name",
    }

    def __init__(self, text_address, var_address):
        self.text_address = unpack_to_int(text_address)
        self.var_address = unpack_to_int(var_address)

        if NetworkTextTranslate.npc_names is None:
            NetworkTextTranslate.npc_names = self.__get_npc_names()

        category = read_string(self.var_address + 40)  # var name is 40 bytes in
        if category in NetworkTextTranslate.translate:
            if category == "B_TARGET_RPL":  # key used for 自分
                write_string(self.text_address, "self")
                return
            elif category in ["M_pc", "M_npc", "B_ACTOR", "B_TARGET", "C_PC", "L_SENDER_NAME"]:  # npc or player names
                name = read_string(self.text_address)
                if name in NetworkTextTranslate.npc_names:
                    name_to_write = NetworkTextTranslate.npc_names[name]
                else:
                    name_to_write = convert_into_eng(name)
                write_string(self.text_address, name_to_write)
            elif category == "M_00":
                # can't figure out how to distinguish between strings, so we can't
                # do anything with this right now.
                pass
            elif category == "M_kaisetubun":
                # this captures story so far AND monster trivia.
                # I don't know if this is a sure way to distinguish, but it
                # works so far.
                check_if_story = read_bytes(self.var_address + 36, 4)
                if check_if_story == b"\xC0\x01\x00\x00":
                    story_desc = read_string(self.text_address)
                    translated = self.__translate_story(story_desc)
                    if translated:
                        write_string(self.text_address, translated)
        return


    def __get_npc_names(self):
        """
        Merges all NPC names/monster files to make one dict for searching.
        """
        npc_files = merge_jsons([
            f"{NetworkTextTranslate.misc_files}/custom_npc_names.json",
            f"{NetworkTextTranslate.misc_files}/custom_player_names.json",
            f"{NetworkTextTranslate.misc_files}/subPackage02Client.win32.json",
            f"{NetworkTextTranslate.misc_files}/smldt_msg_pkg_NPC_DB.win32.json",
        ])

        return npc_files


    def __translate_story(self, text: str):
        """
        tbd.
        """
        translator = Translate()
        if story_text := sqlite_read(
            text_to_query=text,
            language=Translate.region_code,
            table="story_so_far"
        ):
            return story_text

        full_text = re.sub("\n", " ", text)
        if translation := translator.translate(full_text):
            formatted_translation = textwrap.fill(
                translation, width=39,
                replace_whitespace=False,
                max_lines=8,
                placeholder="..."
            )
            sqlite_write(
                source_text=text,
                table="story_so_far",
                translated_text=formatted_translation,
                language=Translate.region_code
            )
            return formatted_translation
        return None


def network_text_shellcode(ecx_address: int, esp_address, debug: bool) -> str:

    local_paths = dumps(sys.path).replace("\\", "\\\\")
    log_path = os.path.join(os.path.abspath('.'), 'out.log').replace("\\", "\\\\")

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

    return str(shellcode)
