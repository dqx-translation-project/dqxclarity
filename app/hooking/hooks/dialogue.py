from common.db_ops import init_db, search_bad_strings, sql_read
from common.translate import detect_lang, Translator
from loguru import logger as log

_translator = None


def _init_translator():
    """Initialize the translator if not already loaded."""
    global _translator

    if _translator is not None:
        return _translator

    _translator = Translator()
    return _translator


def dialogue_replacement(original_text: str, npc_name: str = "No_NPC") -> str:
    """Replace dialogue text using the translation logic from the parent Dialog
    class.

    :param original_text: The original Japanese text to translate.
    :param npc_name: Name of the NPC.
    """
    _init_translator()

    # check if text is in Japanese (only translate if needed)
    if not detect_lang(original_text):
        return original_text

    # check bad_strings table for known problematic translations
    bad_strings_result = search_bad_strings(original_text)
    if bad_strings_result:
        return bad_strings_result

    # check database for existing translation
    db_result = sql_read(text=original_text, table="dialog")
    if db_result:
        return db_result

    # translate the text
    translated_text = _translator.translate(text=original_text, wrap_width=46)

    if translated_text:
        # write to database for future lookups
        try:
            conn, cursor = init_db()
            escaped_original = original_text.replace("'", "''")
            escaped_translated = translated_text.replace("'", "''")
            escaped_npc_name = npc_name.replace("'", "''")

            select_query = f"SELECT ja FROM dialog WHERE ja = '{escaped_original}'"
            results = cursor.execute(select_query)

            if results.fetchone() is None:
                # insert new translation with NPC name
                insert_query = f"INSERT INTO dialog (ja, npc_name, en) VALUES ('{escaped_original}', '{escaped_npc_name}', '{escaped_translated}')"
                cursor.execute(insert_query)
            else:
                # update existing translation
                update_query = f"UPDATE dialog SET en = '{escaped_translated}' WHERE ja = '{escaped_original}'"
                cursor.execute(update_query)

            conn.commit()
        except Exception as e:
            print(f"[WARNING] Failed to write to database: {e}")
        finally:
            if conn:
                conn.close()

        return translated_text

    # if translation failed, return original
    return original_text


def on_message(message, data, script):
    """Message handler for dialogue hook.

    Args:
        message: Message dict from Frida script
        data: Binary data (if any) from Frida script
        script: Frida script instance for posting responses
    """
    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload.get('type', 'unknown')

        if msg_type == 'get_replacement':
            original_text = payload.get('text', '')
            npc_name = payload.get('npc_name', 'Unknown')

            try:
                replacement = dialogue_replacement(original_text, npc_name)

                orig_preview = original_text[:40] + "..." if len(original_text) > 40 else original_text
                log.debug(f"{orig_preview}")

            except Exception as e:
                log.exception(f"Replacement failed: {e}")

                # use original text as fallback
                replacement = original_text

            # send the replacement back to frida
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
