from common.db_ops import generate_m00_dict, sql_read
from common.lib import get_project_root, setup_logger
from common.memory import MemWriter
from common.translate import detect_lang, transliterate_player_name
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
        "M_item": "mail_preview",
        "L_OWNER": "pc_name",
        "L_URINUSI": "pc_name",
        "M_NAME": "pc_name",
        "L_PLAYER_NAME": "pc_name",
        "L_QUEST": "quest_name",
        "C_ITMR_STITLE": "top_left_text",
        "CAS_gambler": "casino_name",
        "CAS_target": "casino_target_name",
        "C_MERCENARY": "hired_name",
        "C_STR2": "casino_item_string",
        "L_MONSTERNAME": "housing_monster_name",
        "L_GOODS": "dqx_shop_items",
        "EV_QUEST_NAME": "cutscene_quest_name"
    }

    # explicitly ignore known vars. we want to log any new ones we see just in case
    # there's something of interest in them.
    to_ignore = [
        "M_Hankaku",
        "M_katagaki2",
        "W_MAP_NAME",  # maybe an idea to write the map you're on to the db?
        "M_timei",
        "W_REP_MAX_2ND_R",
        "W_REP_MAX_2ND_F",
        "B_TARGET_ID",
        "M_mp_hp",
        "B_ITEM",
        "B_ACTOR_ID",
        "B_TARGET_ID",
        "B_TARGET2_ID",
        "B_ACTION",
        "B_TARGET2",
        "B_renkin1",
        "B_kakko",
        "B_renkindiff",
        "B_plusminus",
        "M_plusnum",
        "B_VALUE",
        "B_VALUE2",
        "B_VALUE3",
        "B_VALUE4",
        "B_VALUE5",
        "B_VALUE6",
        "M_caption",
        "M_tuyosa",
        "Param1",
        "Param2",
        "Param3",
        "B_RANK",
        "M_rurastone",
        "M_sub",
        "M_dot",
        "M_TXT_00",
        "M_skill1",
        "M_01",
        "M_rare",
        "M_fugou",
        "M_num1",
        "M_emote",
        "M_3PLeader1",
        "M_3PLeader2",
        "M_3PLeader3",
        "C_STR1",
        "_MVER1",
        "_MVER2",
        "_MVER3",
        "W_DELIMITER",
        "M_slogan",
        "M_team",
        "M_monster",
        "M_speaker",
        "M_chat",
        "M_CW_stamp",
        "CAS_monster",
        "CAS_action"
    ]


    def __init__(self, text_address, var_address):
        if not NetworkTextTranslate.writer:
            NetworkTextTranslate.writer = MemWriter()
        self.text_address = NetworkTextTranslate.writer.unpack_to_int(text_address)
        self.var_address = NetworkTextTranslate.writer.unpack_to_int(var_address)

        var_name = self.var_address

        try:
            category = NetworkTextTranslate.writer.read_string(var_name)
            text = NetworkTextTranslate.writer.read_string(self.text_address)
        except UnicodeDecodeError:
            category = ""
            text = ""

        # when we are on the login screen, this hook hits too soon. we don't want to
        # prematurely init the dict as the database hasn't replace our placehold tags
        # with player names. we see _MVER1, _MVER2, etc when we first log in.
        if NetworkTextTranslate.m00_text is None and not category.startswith("_MVER"):
            NetworkTextTranslate.m00_text = generate_m00_dict()

        if category in NetworkTextTranslate.translate:
            # "self" text when a player/monster uses a spell/skill on themselves
            if category == "B_TARGET_RPL":
                if text == "自分":
                    NetworkTextTranslate.writer.write_string(self.text_address, "self")

            # npc or player names
            elif category in ["M_pc", "M_npc", "B_ACTOR", "B_TARGET", "C_PC", "L_SENDER_NAME", "M_OWNER", "M_hiryu", "L_HIRYU", "L_HIRYU_NAME", "M_name", "L_OWNER", "L_URINUSI", "M_NAME", "L_PLAYER_NAME", "CAS_gambler", "CAS_target", "C_MERCENARY", "L_MONSTERNAME"]:
                if NetworkTextTranslate.m00_text.get(text):
                    name_to_write = NetworkTextTranslate.m00_text[text]
                else:
                    name_to_write = transliterate_player_name(text)

                # the original strength length (in bytes) must be the exact same size as what we write, or the string will break.
                orig_len = len(text.encode('utf-8'))
                new_len = len(name_to_write.encode('utf-8'))

                if new_len > orig_len:
                    name_to_write = name_to_write[:orig_len]
                elif new_len < orig_len:
                    # we need to pad the string with spaces until it's the same length as orig_len.
                    while len(name_to_write.encode('utf-8')) <= orig_len:
                        name_to_write += " "

                NetworkTextTranslate.writer.write_string(self.text_address, name_to_write)

            # generic string
            elif category in ["M_00", "C_QUEST", "M_02", "M_header", "M_item", "L_QUEST", "C_ITMR_STITLE", "C_STR2", "L_GOODS", "EV_QUEST_NAME"]:
                if to_write := NetworkTextTranslate.m00_text.get(text):

                    # the default string buffer looks to be a size of 16 bytes (last byte is a null terminator).
                    # if the original string is longer than 16 bytes, we'll truncate to the length of the original
                    # size instead. without this, accepting a quest during a cutscene has the potential to throw an
                    # exception.
                    if category == "EV_QUEST_NAME":
                        orig_len = len(text.encode('utf-8'))
                        if orig_len <= 15:
                            to_write = to_write[:15]
                        else:
                            to_write = to_write[:orig_len]

                    NetworkTextTranslate.writer.write_string(self.text_address, to_write)
                else:
                    if category == "M_00":
                        text = self.__format_to_json(text)
                    NetworkTextTranslate.custom_text_logger.info(f"--\n>>{category} ::\n{text}")

            # this captures story so far AND monster trivia.
            # unfortunately, unsure of how to figure out which one is focused
            # on story_so_far, but if it isn't in the db, we will just log it.
            elif category == "M_kaisetubun":
                if detect_lang(text):
                    translated = self.__translate_story(text)
                    if translated:
                        # we need to truncate the string if the length of the japanese
                        # string is shorter than the english string, or we'll write over
                        # game data and cause a crash.
                        story_desc_len = len(bytes(text, encoding="utf-8"))
                        NetworkTextTranslate.writer.write_string(self.text_address, translated[:story_desc_len])
                    else:
                        NetworkTextTranslate.custom_text_logger.info(f"--\n{category} ::\n{text}")
        elif category in NetworkTextTranslate.to_ignore:
            return
        else:
            if category and text:
                NetworkTextTranslate.custom_text_logger.info(f"--\n{category} ::\n{text}")

        return


    def __translate_story(self, text: str):
        """Looks up text in the story_so_far table for story text. If found,
        returns the text.

        :param text: Text of the current page of the story.
        :returns: Translated text.
        """
        if story_text := sql_read(
            text=text,
            table="story_so_far"
        ):
            return story_text

        return None


    def __format_to_json(self, text: str):
        replaced = text.replace("\n", "\\n")
        return f'{{\n  "1": {{\n    "{replaced}": ""\n  }}\n}}'


def network_text_shellcode(edx_address: int, ebx_address) -> str:

    local_paths = dumps(sys.path).replace("\\", "\\\\")
    log_path = os.path.join(os.path.abspath('.'), 'logs\\console.log').replace("\\", "\\\\")

    shellcode = rf"""
try:
    import sys
    import traceback
    sys.path = {local_paths}
    from hooking.network_text import NetworkTextTranslate
    NetworkTextTranslate({edx_address}, {ebx_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return shellcode
