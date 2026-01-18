"""Hooks network text template string replacements."""

from common.db_ops import generate_m00_dict, sql_read
from common.lib import get_project_root, setup_logger
from common.translate import is_text_japanese, transliterate_player_name
from loguru import logger as log


# Module-level cache and logger
_m00_text = None
_custom_text_logger = None

_translate_categories = {
    "<%sM_pc>",
    "<%sM_npc>",
    "<%sL_SENDER_NAME>",
    "<%sB_TARGET_RPL>",
    "<%sM_00>",
    "<%sM_kaisetubun>",
    "<%sC_QUEST>",
    "<%sC_PC>",
    "<%sM_OWNER>",
    "<%sM_hiryu>",
    "<%sL_HIRYU>",
    "<%sL_HIRYU_NAME>",
    "<%sM_name>",
    "<%sM_02>",
    "<%sM_header>",
    "<%sM_item>",
    "<%sL_OWNER>",
    "<%sL_URINUSI>",
    "<%sM_NAME>",
    "<%sL_PLAYER_NAME>",
    "<%sL_QUEST>",
    "<%sC_ITMR_STITLE>",
    "<%sCAS_gambler>",
    "<%sCAS_target>",
    "<%sC_MERCENARY>",
    "<%sC_STR2>",
    "<%sL_MONSTERNAME>",
    "<%sEV_QUEST_NAME>",
}

# categories to ignore (known but not translated)
_to_ignore = {
    "<%sM_Hankaku>",
    "<%sM_katagaki2>",
    "<%sW_MAP_NAME>",
    "<%sM_timei>",
    "<%sW_REP_MAX_2ND_R>",
    "<%sW_REP_MAX_2ND_F>",
    "<%sB_TARGET_ID>",
    "<%sM_mp_hp>",
    "<%sB_ITEM>",
    "<%sB_ACTOR_ID>",
    "<%sB_TARGET2_ID>",
    "<%sB_ACTION>",
    "<%sB_TARGET2>",
    "<%sB_renkin1>",
    "<%sB_kakko>",
    "<%sB_renkindiff>",
    "<%sB_plusminus>",
    "<%sM_plusnum>",
    "<%sB_VALUE>",
    "<%sB_VALUE2>",
    "<%sB_VALUE3>",
    "<%sB_VALUE4>",
    "<%sB_VALUE5>",
    "<%sB_VALUE6>",
    "<%sM_caption>",
    "<%sM_tuyosa>",
    "<%sParam1>",
    "<%sParam2>",
    "<%sParam3>",
    "<%sB_RANK>",
    "<%sM_rurastone>",
    "<%sM_sub>",
    "<%sM_dot>",
    "<%sM_TXT_00>",
    "<%sM_skill1>",
    "<%sM_01>",
    "<%sM_rare>",
    "<%sM_fugou>",
    "<%sM_num1>",
    "<%sM_emote>",
    "<%sM_3PLeader1>",
    "<%sM_3PLeader2>",
    "<%sM_3PLeader3>",
    "<%sC_STR1>",
    "<%s_MVER1>",
    "<%s_MVER2>",
    "<%s_MVER3>",
    "<%sW_DELIMITER>",
    "<%sM_slogan>",
    "<%sM_team>",
    "<%sM_monster>",
    "<%sM_speaker>",
    "<%sM_chat>",
    "<%sM_CW_stamp>",
    "<%sCAS_monster>",
    "<%sCAS_action>",
    "<%sB_ACTOR>",
    "<%sB_TARGET>",
    "<%sL_GOODS>",
}


def _init_data():
    """Initialize the m00 text database if not already loaded."""
    global _m00_text, _custom_text_logger

    if _m00_text is not None:
        return _m00_text

    _m00_text = generate_m00_dict()
    _custom_text_logger = setup_logger("text_logger", get_project_root("logs/custom_text.log"))

    return _m00_text


def _format_to_json(text: str) -> str:
    """Format text for logging as JSON."""
    replaced = text.replace("\n", "\\n")
    return f'{{\n  "1": {{\n    "{replaced}": ""\n  }}\n}}'


def network_text_replacement(original_text: str, category: str) -> str:
    """Replace network text based on category.

    :param original_text: The original text to replace.
    :param category: The category/variable name.
    :return: Replacement text, or original if no replacement.
    """
    # only process Japanese text
    if not is_text_japanese(original_text):
        return original_text

    # this hook hits on login screen, but we don't init data until player is logged in.
    # if we see this string, we ignore it. (categories starting with _MVER)
    if category.startswith("Version <%s_MVER"):
        return original_text

    m00_text = _init_data()

    if category in _to_ignore:
        return original_text

    if category not in _translate_categories:
        # log unknown category
        if category and original_text:
            _custom_text_logger.info(f"--\n{category} ::\n{original_text}")
        return original_text

    if category == "<%sB_TARGET_RPL>":
        # "self" text when player/monster uses spell on themselves
        if original_text == "自分":
            return "self"

    elif category in {
        "<%sM_pc>",
        "<%sM_npc>",
        "<%sC_PC>",
        "<%sL_SENDER_NAME>",
        "<%sM_OWNER>",
        "<%sM_hiryu>",
        "<%sL_HIRYU>",
        "<%sL_HIRYU_NAME>",
        "<%sM_name>",
        "<%sL_OWNER>",
        "<%sL_URINUSI>",
        "<%sM_NAME>",
        "<%sL_PLAYER_NAME>",
        "<%sCAS_gambler>",
        "<%sCAS_target>",
        "<%sC_MERCENARY>",
        "<%sL_MONSTERNAME>",
    }:
        # NPC or player names
        if m00_text.get(original_text):
            return m00_text[original_text]
        else:
            return transliterate_player_name(original_text)

    elif category in {
        "<%sM_00>",
        "<%sC_QUEST>",
        "<%sM_02>",
        "<%sM_header>",
        "<%sM_item>",
        "<%sL_QUEST>",
        "<%sC_ITMR_STITLE>",
        "<%sC_STR2>",
        "<%sEV_QUEST_NAME>",
    }:
        # generic string
        if replacement := m00_text.get(original_text):
            return replacement
        else:
            # log missing translation
            log_text = _format_to_json(original_text) if category == "<%sM_00>" else original_text
            _custom_text_logger.info(f"--\n>>{category} ::\n{log_text}")
            return original_text

    elif category == "<%sM_kaisetubun>" and is_text_japanese(original_text):
        # Story so far AND monster trivia
        if story_text := sql_read(text=original_text, table="story_so_far"):
            # truncate to original length to avoid overwriting game data
            story_desc_len = len(bytes(original_text, encoding="utf-8"))
            return story_text[:story_desc_len]
        else:
            _custom_text_logger.info(f"--\n{category} ::\n{original_text}")
            return original_text

    return original_text


def on_message(message, data, script):
    """Message handler for network_text hook.

    Args:
        message: Message dict from Frida script
        data: Binary data (if any) from Frida script
        script: Frida script instance for posting responses
    """
    if message["type"] == "send":
        payload = message["payload"]
        msg_type = payload.get("type", "unknown")

        if msg_type == "get_replacement":
            # frida is requesting a replacement
            original_text = payload.get("text", "")
            category = payload.get("category", "")

            try:
                replacement = network_text_replacement(original_text, category)

            except Exception as e:
                log.exception(f"Replacement failed: {e}")

                # use original text as fallback
                replacement = original_text

            # send the replacement back to Frida
            log.trace(f"{original_text} => {replacement}")
            script.post({"type": "replacement", "text": replacement})

        elif msg_type == "info":
            log.debug(f"{payload['payload']}")
        elif msg_type == "error":
            log.error(f"{payload['payload']}")
        else:
            log.debug(f"{payload}")

    elif message["type"] == "error":
        log.error(f"[JS ERROR] {message.get('stack', message)}")
