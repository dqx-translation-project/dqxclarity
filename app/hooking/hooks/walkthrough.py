"""Hooks walkthrough text replacements."""
from common.db_ops import sql_read, sql_write
from common.translate import Translator
from loguru import logger as log

import regex

_translator = None
_jp_regex = regex.compile(r"\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Han}")


def _init_translator():
    """Initialize the translator if not already loaded."""
    global _translator

    if _translator is not None:
        return _translator

    _translator = Translator()
    return _translator


def _is_japanese(text: str) -> bool:
    """Check if text contains Japanese characters."""
    return bool(_jp_regex.search(text))


def walkthrough_replacement(original_text: str) -> str:
    """Replace walkthrough text using database lookup or translation.

    :param original_text: The original text to replace.
    :return: Replacement text, or original if no replacement.
    """
    # only process Japanese text
    if not _is_japanese(original_text):
        return original_text

    # check database first
    result = sql_read(text=original_text, table="walkthrough")

    if result:
        return result
    else:
        # not in database - translate it
        translator = _init_translator()
        translated_text = translator.translate(
            text=original_text, wrap_width=31, max_lines=3, add_brs=False
        )

        # save to database for future lookups
        sql_write(
            source_text=original_text,
            translated_text=translated_text,
            table="walkthrough"
        )

        return translated_text


def on_message(message, data, script):
    """Message handler for walkthrough hook.

    :param message: Message dict from Frida script
    :param data: Binary data (if any) from Frida script
    :param script: Frida script instance for posting responses
    """
    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload.get('type', 'unknown')

        if msg_type == 'get_replacement':
            # Frida is requesting a replacement
            original_text = payload.get('text', '')

            try:
                replacement = walkthrough_replacement(original_text)

            except Exception as e:
                log.exception(f"Replacement failed: {e}")

                # use original text as fallback
                replacement = original_text

            # send the replacement back to Frida
            script.post({
                'type': 'replacement',
                'text': replacement
            })

        elif msg_type == 'info':
            log.debug(f"{payload['payload']}")
        elif msg_type == 'error':
            log.error(f"{payload['payload']}")
        else:
            log.debug(f"{payload}")

    elif message['type'] == 'error':
        log.error(f"[JS ERROR] {message.get('stack', message)}")
