"""Hooks entity nameplate replacements using database lookups and
transliteration."""

import regex
from common.db_ops import generate_m00_dict
from common.translate import transliterate_player_name
from loguru import logger as log


# Module-level cache
_names = None
_jp_regex = regex.compile(r"\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Han}")


def _init_names():
    """Initialize the nameplate database if not already loaded."""
    global _names

    if _names is not None:
        return _names

    # load databases with priority
    monsters = generate_m00_dict(files="'monsters'")
    npcs = generate_m00_dict(files="'npcs', 'custom_npc_name_overrides'")
    mytown = generate_m00_dict(files="'custom_concierge_mail_names'")
    player_custom = generate_m00_dict(files="'local_player_names', 'local_mytown_names'")

    _names = {**monsters, **npcs, **mytown, **player_custom}

    return _names


def _is_japanese(text: str) -> bool:
    """Check if text contains Japanese characters."""
    return bool(_jp_regex.search(text))


def nameplate_replacement(original_name: str) -> str:
    """Replace nameplate using database lookup or transliteration.

    :param original_name: The original name to replace.
    :return: Replacement name with \x04 prefix, or original if no
        replacement.
    """
    # only process Japanese text
    if not _is_japanese(original_name):
        return original_name

    names = _init_names()

    # check database first
    result = names.get(original_name)

    if not result:
        # must be a player name?
        result = transliterate_player_name(original_name)

    # prepend \x04 prefix to replacement. we do this because without it, player
    # names turn red and their chat picture is a GM avatar.
    log.trace(f"{original_name} => {result}")
    return "\x04" + result


def on_message(message, data, script):
    """Message handler for nameplates hook.

    :param message: Message dict from Frida script
    :param data: Binary data (if any) from Frida script
    :param script: Frida script instance for posting responses
    """
    if message["type"] == "send":
        payload = message["payload"]
        msg_type = payload.get("type", "unknown")

        if msg_type == "get_replacement":
            original_name = payload.get("name", "")

            try:
                replacement = nameplate_replacement(original_name)

            except Exception as e:
                log.exception(f"Replacement failed: {e}")

                # use original name as fallback
                replacement = original_name

            # send the replacement back to Frida
            script.post({"type": "replacement", "name": replacement})

        elif msg_type == "info":
            log.debug(f"{payload['payload']}")
        elif msg_type == "error":
            log.error(f"{payload['payload']}")
        else:
            log.debug(f"{payload}")

    elif message["type"] == "error":
        log.error(f"[JS ERROR] {message.get('stack', message)}")
