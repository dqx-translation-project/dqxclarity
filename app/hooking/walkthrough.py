import sys
import os
from json import dumps


def walkthrough_shellcode(
    esi_address: int, api_service: str, api_key: str, api_logging: str, api_region: str, debug: bool
) -> str:
    """
    Returns shellcode for the walkthrough function hook.
    ebx_address: Where text can be modified to be fed to the screen
    """
    local_paths = dumps(sys.path).replace("\\", "\\\\")
    working_dir = dumps(os.getcwd()).replace("\\", "\\\\")

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
        result = sqlite_read(walkthrough_str, '{api_region}', 'walkthrough')

        if result is not None:
            logger.debug('Found database entry. No translation was needed.')
            write_bytes(walkthrough_addr, result.encode() + b'\x00')
        else:
            logger.debug('Translation is needed for ' + str(len(walkthrough_str)) + ' characters. Sending to {api_service}')
            translated_text = sanitized_dialog_translate('{api_service}', walkthrough_str, '{api_key}', '{api_region}', text_width=31)
            sqlite_write(walkthrough_str, 'walkthrough', translated_text, '{api_region}')
            write_bytes(walkthrough_addr, translated_text.encode() + b'\x00')
    chdir(og_working_dir)
except Exception as e:
    with open('out.log', 'a+') as f:
        f.write(e)
    """

    return str(shellcode)
