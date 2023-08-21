from common.db_ops import sql_read, sql_write
from common.lib import get_abs_path, merge_jsons, setup_logger
from common.memory import read_bytes, read_string, unpack_to_int, write_string
from common.translate import convert_into_eng, Translate
from json import dumps
from loguru import logger

import os
import sys


class NetworkTextTranslate:

    misc_files = "/".join([get_abs_path(__file__), "../misc_files"])
    custom_text_logger = setup_logger("text_logger", "/".join([get_abs_path(__file__), "../logs/custom_text.log"]))
    npc_names = None
    m00_text = None

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
        "M_OWNER": "house_owner"
    }

    def __init__(self, text_address, var_address):
        self.text_address = unpack_to_int(text_address)
        self.var_address = unpack_to_int(var_address)

        if NetworkTextTranslate.npc_names is None:
            NetworkTextTranslate.npc_names = self.__get_npc_names()

        if NetworkTextTranslate.m00_text is None:
            NetworkTextTranslate.m00_text = self.__get_m00_text()

        category = read_string(self.var_address + 40)  # var name is 40 bytes in
        if category in NetworkTextTranslate.translate:
            if category == "B_TARGET_RPL":
                self_text = read_string(self.text_address)
                if self_text == "自分":
                    write_string(self.text_address, "self")
                return
            elif category in ["M_pc", "M_npc", "B_ACTOR", "B_TARGET", "C_PC", "L_SENDER_NAME", "M_OWNER"]:  # npc or player names
                name = read_string(self.text_address)
                if name in NetworkTextTranslate.npc_names:
                    name_to_write = NetworkTextTranslate.npc_names[name]
                else:
                    name_to_write = convert_into_eng(name)
                write_string(self.text_address, name_to_write)
            elif category in ["M_00", "C_QUEST"]:
                m00_string = read_string(self.text_address)
                if m00_string in NetworkTextTranslate.m00_text:
                    to_write = NetworkTextTranslate.m00_text[m00_string]
                    if to_write != "":
                        write_string(self.text_address, to_write)
                else:
                    NetworkTextTranslate.custom_text_logger.info(f"--\n>>m00_str:\n{m00_string}")
            elif category == "M_kaisetubun":
                # this captures story so far AND monster trivia.
                # I don't know if this is a sure way to distinguish, but it
                # works so far.
                check_if_story = read_bytes(self.var_address + 36, 4)
                if check_if_story == b"\xC0\x01\x00\x00":
                    story_desc = read_string(self.text_address)
                    translated = self.__translate_story(story_desc)
                    if translated:
                        # we need to truncate the string if the length of the japanese
                        # string is shorter than the english string, or we'll write over
                        # game data and cause a crash.
                        story_desc_len = len(bytes(story_desc, encoding="utf-8"))
                        logger.debug("Wrote story so far.")
                        write_string(self.text_address, translated[:story_desc_len])
        else:
            NetworkTextTranslate.custom_text_logger.info(f"--\n{category} :: {read_string(self.text_address)}")
        return


    def __get_npc_names(self):
        """Merges all NPC names/monster files to make one dict for
        searching."""
        npc_files = merge_jsons([
            f"{NetworkTextTranslate.misc_files}/custom_npc_names.json",
            f"{NetworkTextTranslate.misc_files}/custom_player_names.json",
            f"{NetworkTextTranslate.misc_files}/subPackage02Client.win32.json",
            f"{NetworkTextTranslate.misc_files}/smldt_msg_pkg_NPC_DB.win32.json",
        ])

        return npc_files


    def __get_m00_text(self):
        m00_text = merge_jsons([
            f"{NetworkTextTranslate.misc_files}/custom_master_quests.json",
            f"{NetworkTextTranslate.misc_files}/custom_team_quests.json",
            f"{NetworkTextTranslate.misc_files}/eventTextSysQuestaClient.json",
            f"{NetworkTextTranslate.misc_files}/custom_episode_request_book.json",
            f"{NetworkTextTranslate.misc_files}/custom_trainee_logbook.json",
            f"{NetworkTextTranslate.misc_files}/custom_mail.json",
            f"{NetworkTextTranslate.misc_files}/custom_lottery_prizes.json",
        ])

        return m00_text


    def __translate_story(self, text: str):
        """Looks up text in the story_so_far table for story text. If found,
        returns the text. If not, translates it on the fly and writes it to
        memory.

        :param text: Text of the current page of the story.
        :returns: Translated text.
        """
        translator = Translate()
        if story_text := sql_read(
            text=text,
            table="story_so_far",
            language=Translate.region_code,
        ):
            return story_text

        if translation := translator.sanitize_and_translate(text, wrap_width=39, max_lines=8, add_brs=False):
            sql_write(
                source_text=text,
                translated_text=translation,
                table="story_so_far",
                language=Translate.region_code
            )
            return translation
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
    return str(shellcode)
