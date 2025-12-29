from common.db_ops import generate_m00_dict, sql_read, sql_write
from common.translate import clean_up_and_return_items, Translator
from loguru import logger as log

import regex

_jp_regex = regex.compile(r"\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Han}")
_quests = None
_translator = Translator()


def _is_japanese(text: str) -> bool:
    """Check if text contains Japanese characters."""
    return bool(_jp_regex.search(text))


def _query_quest(text: str) -> str:
    """Query quest data from pre-generated dict."""
    global _quests
    if _quests is None:
        _quests = generate_m00_dict(files="'quests'")

    return _quests.get(text, None)


def _translate_quest_desc(text: str) -> str:
    """Translate quest description using DB cache or translator."""
    if db_quest_text := sql_read(text=text, table="quests"):
        return db_quest_text

    if translation := _translator.translate(text, wrap_width=49, max_lines=6, add_brs=False):
        sql_write(source_text=text, translated_text=translation, table="quests")
        return translation

    return None


def process_quest_data(data: dict) -> dict:
    """Process quest data received from Frida and return replacements.

    :param data: Dict containing quest strings from Frida:
        - subquestName: Subquest name
        - questName: Quest name
        - questDesc: Quest description
        - questRewards: Quest rewards text
        - questRepeatRewards: Repeat quest rewards text
    :returns: Dict with replacement strings (only includes fields that need updating)
    """
    # extract original strings
    subquest_name = data.get('subquestName', '')
    quest_name = data.get('questName', '')
    quest_desc = data.get('questDesc', '')
    quest_rewards = data.get('questRewards', '')
    quest_repeat_rewards = data.get('questRepeatRewards', '')

    # check if text is Japanese
    is_ja = _is_japanese(quest_desc)

    replacements = {}

    if is_ja:
        if subquest_name:
            if replacement := _query_quest(subquest_name):
                replacements['subquestName'] = replacement

        if quest_name:
            if replacement := _query_quest(quest_name):
                replacements['questName'] = replacement

        if quest_desc:
            if replacement := _translate_quest_desc(quest_desc):
                replacements['questDesc'] = replacement

        if quest_rewards:
            if replacement := clean_up_and_return_items(quest_rewards):
                replacements['questRewards'] = replacement

        if quest_repeat_rewards:
            if replacement := clean_up_and_return_items(quest_repeat_rewards):
                replacements['questRepeatRewards'] = replacement

    return replacements


def on_message(message, data, script):
    """Message handler for accept_quest hook.

    :param message: Message dict from Frida script
    :param data: Binary data (if any) from Frida script
    :param script: Frida script instance for posting responses
    """
    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload.get('type', 'unknown')

        if msg_type == 'quest_data':
            quest_data = payload.get('data', {})

            try:
                replacements = process_quest_data(quest_data)

                quest_name_preview = quest_data.get('questName', 'Unknown')[:50]
                if replacements:
                    log.debug(f"Processed: {quest_name_preview} ({len(replacements)} fields translated)")
                else:
                    log.debug(f"No translation needed: {quest_name_preview}")

            except Exception as e:
                log.exception(f"Processing failed: {e}")
                replacements = {}

            # send replacements back to Frida
            script.post({
                'type': 'quest_replacements',
                'data': replacements
            })

        elif msg_type == 'info':
            log.debug(f"{payload['payload']}")
        elif msg_type == 'error':
            log.error(f"{payload['payload']}")
        else:
            log.debug(f"{payload}")

    elif message['type'] == 'error':
        log.error(f"[JS ERROR] {message.get('stack', message)}")
