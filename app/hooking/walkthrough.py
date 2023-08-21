from common.translate import Translate
from json import dumps

import os
import sys


def walkthrough_shellcode(
    esi_address: int, api_logging: str, debug: bool
) -> str:
    """
    Returns shellcode for the walkthrough function hook.
    ebx_address: Where text can be modified to be fed to the screen
    """
    local_paths = dumps(sys.path).replace("\\", "\\\\")
    working_dir = dumps(os.getcwd()).replace("\\", "\\\\")
    Translate()
    region_code = Translate.region_code

    shellcode = rf"""
try:
    import sys
    from os import chdir, getcwd

    local_paths = {local_paths}
    working_dir = {working_dir}
    debug = {debug}
    api_logging = {api_logging}
    region_code = '{region_code}'

    sys.path = local_paths
    og_working_dir = getcwd()
    chdir(working_dir)

    from common.lib import setup_logger
    from common.memory import (
        write_bytes,
        read_string)
    from common.translate import (
        sanitized_dialog_translate,
        sqlite_read,
        sqlite_write,
        detect_lang,
        common.hook)

    logger = setup_logger('out', 'out.log')
    game_text_logger = setup_logger('gametext', 'game_text.log')

    walkthrough_addr = unpack_to_int({esi_address})
    walkthrough_str = read_string(walkthrough_addr)

    if detect_lang(walkthrough_str):
        logger.debug('Walkthrough text: ' + str(walkthrough_str))
        result = sqlite_read(walkthrough_str, region_code, 'walkthrough')

        if result is not None:
            logger.debug('Found database entry. No translation was needed.')
            write_bytes(walkthrough_addr, result.encode() + b'\x00')
        else:
            logger.debug('Translation is needed for ' + str(len(walkthrough_str)) + ' characters.')
            translated_text = sanitized_dialog_translate(walkthrough_str, text_width=31)
            sqlite_write(walkthrough_str, 'walkthrough', translated_text, region_code)
            write_bytes(walkthrough_addr, translated_text.encode() + b'\x00')
    chdir(og_working_dir)
except Exception as e:
    with open('out.log', 'a+') as f:
        f.write(str(e))
    """

    return str(shellcode)
