import requests
from common.config import UserConfig
from common.constants import COMMUNITY_STRING_API_URL
from common.db_ops import init_db, search_bad_strings, sql_read
from common.measure import measure_duration
from common.translate import Translator, get_player_name, is_text_japanese
from loguru import logger as log


_translator = None
_userconfig = None


def _init_locals():
    """Initialize locals if not already loaded."""
    global _translator
    global _userconfig

    if not _translator:
        _translator = Translator()

    if not _userconfig:
        _userconfig = UserConfig()


def dialogue_replacement(original_text: str, npc_name: str = "No_NPC") -> str:
    """Replace dialogue text using the translation logic from the parent Dialog
    class.

    :param original_text: The original Japanese text to translate.
    :param npc_name: Name of the NPC.
    """
    _init_locals()

    # check if text is in Japanese (only translate if needed)
    if not is_text_japanese(original_text):
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
        send_string_to_community_api(original_text=original_text, translated_text=translated_text, npc_name=npc_name)

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
                insert_query = f"INSERT INTO dialog (ja, npc_name, en) VALUES ('{escaped_original}', '{escaped_npc_name}', '{escaped_translated}')"  # noqa: E501
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


@measure_duration
def send_string_to_community_api(original_text: str, translated_text: str, npc_name: str) -> bool:
    """Submits string to the community api if user enabled it."""
    if not _userconfig.community_enabled:
        return None

    # we need to retrieve the player's name and sibling name each call in case
    # they change characters.
    player, sibling = get_player_name()

    # attempt to replace player/sibling names with placeholders
    text_with_placeholders = original_text.replace(player, "<pnplacehold>")
    text_with_placeholders = text_with_placeholders.replace(sibling, "<snplacehold>")

    # don't use the translated text if the placeholders were added. this would submit
    # the player's name in the translated text, which we don't want.
    if original_text != text_with_placeholders:
        translated_text = text_with_placeholders

    headers = {
        "Content-Type": "application/json",
        "x-api-key": _userconfig.community_key,
        # must encode to utf-8 as japanese. requests uses latin-1 by default for headers
        "x-character-name": player.encode("utf-8"),
        "x-sibling-name": sibling.encode("utf-8"),
    }
    data = {"jp": text_with_placeholders, "tr": translated_text, "npc_name": npc_name}

    try:
        response = requests.post(COMMUNITY_STRING_API_URL, headers=headers, json=data)
        if response.status_code == 200:
            log.debug("Sent string to community api.")
        else:
            log.warning(
                f"Failed to send string to community api. Status code: {response.status_code}. Error: {response.text}"
            )
    except Exception as e:
        # don't stop the rest of the translation from falling over just because this failed to POST.
        # log the error and keep moving.
        log.exception(f"Failed to send string to community api. Error: {e}")


def on_message(message, data, script):
    """Message handler for dialogue hook.

    Args:
        message: Message dict from Frida script
        data: Binary data (if any) from Frida script
        script: Frida script instance for posting responses
    """
    if message["type"] == "send":
        payload = message["payload"]
        msg_type = payload.get("type", "unknown")

        if msg_type == "get_replacement":
            original_text = payload.get("text", "")
            npc_name = payload.get("npc_name", "Unknown")

            try:
                replacement = dialogue_replacement(original_text, npc_name)

            except Exception as e:
                log.exception(f"Replacement failed: {e}")

                # use original text as fallback
                replacement = original_text

            # send the replacement back to frida
            script.post({"type": "replacement", "text": replacement})

        elif msg_type == "info":
            log.debug(f"{payload['payload']}")
        elif msg_type == "error":
            log.error(f"{payload['payload']}")
        else:
            log.debug(f"{payload}")

    elif message["type"] == "error":
        log.error(f"[JS ERROR] {message.get('stack', message)}")
