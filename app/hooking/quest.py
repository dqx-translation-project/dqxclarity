import sys
import os
from json import dumps
from common.translate import determine_translation_service


def quest_text_shellcode(eax_address: int, debug: bool) -> str:
    """
    Returns shellcode for the translate function hook.
    eax_address: Where text can be modified to be fed to the screen
    """
    local_paths = dumps(sys.path).replace("\\", "\\\\")
    working_dir = dumps(os.getcwd()).replace("\\", "\\\\")

    api_details = determine_translation_service()
    api_service = api_details["TranslateService"]
    api_key = api_details["TranslateKey"]
    api_logging = api_details["EnableDialogLogging"]
    api_region = api_details["RegionCode"]

    shellcode = rf"""
try:
    import sys
    from os import chdir, getcwd

    local_paths = {local_paths}
    working_dir = {working_dir}
    debug = {debug}
    api_logging = {api_logging}

    sys.path = local_paths
    og_working_dir = getcwd()
    chdir(working_dir)

    from common.lib import setup_logger
    from common.memory import (
        write_bytes,
        read_string,
        unpack_to_int)
    from common.translate import (
        query_string_from_file,
        detect_lang,
        clean_up_and_return_items,
        quest_translate)

    logger = setup_logger('out', 'out.log')
    game_text_logger = setup_logger('gametext', 'game_text.log')

    quest_file = 'adhoc_wd_quests_requests'
    quest_addr = unpack_to_int({eax_address})

    subquest_name_addr = quest_addr + 20
    quest_name_addr = quest_addr + 76
    quest_desc_addr = quest_addr + 132
    quest_rewards_addr = quest_addr + 640
    quest_repeat_rewards_addr = quest_addr + 744

    subquest_name_ja = read_string(subquest_name_addr)
    quest_name_ja = read_string(quest_name_addr)
    quest_desc_ja = read_string(quest_desc_addr)
    quest_rewards_ja = read_string(quest_rewards_addr)
    quest_repeat_rewards_ja = read_string(quest_repeat_rewards_addr)

    if detect_lang(quest_desc_ja):
        if subquest_name_ja:
            subquest_name_en = query_string_from_file(subquest_name_ja, quest_file)
            if subquest_name_en:
                write_bytes(subquest_name_addr, str.encode(subquest_name_en) + b'\x00')
        if quest_name_ja:
            quest_name_en = query_string_from_file(quest_name_ja, quest_file)
            if quest_name_en:
                logger.info('Found quest address @ ' + str(hex(quest_name_addr)))
                write_bytes(quest_name_addr, str.encode(quest_name_en) + b'\x00')
        if quest_rewards_ja:
            quest_rewards_en = clean_up_and_return_items(quest_rewards_ja)
            if quest_rewards_en:
                write_bytes(quest_rewards_addr, str.encode(quest_rewards_en) + b'\x00')
        if quest_repeat_rewards_ja:
            quest_repeat_rewards_en = clean_up_and_return_items(quest_repeat_rewards_ja)
            if quest_repeat_rewards_en:
                write_bytes(quest_repeat_rewards_addr, str.encode(quest_repeat_rewards_en) + b'\x00')
        if quest_desc_ja:
            quest_desc_en = quest_translate('{api_service}', quest_desc_ja, '{api_key}', '{api_region}')
            if quest_desc_en:
                write_bytes(quest_desc_addr, str.encode(quest_desc_en) + b'\x00')
    chdir(og_working_dir)
except Exception as e:
    with open('out.log', 'a+') as f:
        f.write(e)
    """

    return str(shellcode)
