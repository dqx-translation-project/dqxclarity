"""Hooks corner text replacements using database lookups."""

from common.db_ops import generate_m00_dict
from common.lib import get_project_root, setup_logger
from loguru import logger as log

import regex

_data = None
_custom_text_logger = None
_jp_regex = regex.compile(r"\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Han}")


def _init_data():
    """Initialize the corner text database if not already loaded."""
    global _data, _custom_text_logger

    if _data is not None:
        return _data

    _data = generate_m00_dict("'custom_corner_text'")
    _custom_text_logger = setup_logger("text_logger", get_project_root("logs/corner_text.log"))

    return _data


def _is_japanese(text: str) -> bool:
    """Check if text contains Japanese characters."""
    return bool(_jp_regex.search(text))


def corner_text_replacement(original_text: str) -> str:
    """Replace corner text using database lookup.

    :param original_text: The original text to replace.
    :return: Replacement text, or original if no replacement found.
    """
    # Only process Japanese text
    if not _is_japanese(original_text):
        return original_text

    data = _init_data()

    if original_text in data:
        replacement = data[original_text]
        if replacement and replacement != "":
            return replacement
    else:
        # Log missing entries
        _custom_text_logger.info(f"--\n>>corner_text ::\n{original_text}")

    return original_text


def on_message(message, data, script):
    """Message handler for corner_text hook.

    :param message: Message dict from Frida script
    :param data: Binary data (if any) from Frida script
    :param script: Frida script instance for posting responses
    """
    if message["type"] == "send":
        payload = message["payload"]
        msg_type = payload.get("type", "unknown")

        if msg_type == "get_replacement":
            original_text = payload.get("text", "")

            try:
                replacement = corner_text_replacement(original_text)

            except Exception as e:
                log.exception(f"Replacement failed: {e}")

                # use original text as fallback
                replacement = original_text

            # send the replacement back to frida
            log.debug(f"\n{original_text}")
            script.post({"type": "replacement", "text": replacement})

        elif msg_type == "info":
            log.debug(f"{payload['payload']}")
        elif msg_type == "error":
            log.error(f"{payload['payload']}")
        else:
            log.debug(f"{payload}")

    elif message["type"] == "error":
        log.error(f"[JS ERROR] {message.get('stack', message)}")
