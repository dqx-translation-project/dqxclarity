import sys
import os
from json import dumps


# this works, but we can't use it due to integrity checks.
def rename_party_members_shellcode(ebx_address: int, debug: bool) -> str:
    """
    Returns shellcode to rename party members into Romaji.
    ebx_address: Where text can be modified
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

    sys.path = local_paths
    og_working_dir = getcwd()
    chdir(working_dir)

    from common.lib import setup_logger
    from common.memory import read_string, write_string, unpack_to_int
    from common.translate import convert_into_eng

    logger = setup_logger('out', 'out.log')

    player_addr = unpack_to_int({ebx_address})
    player_addr_name = player_addr + 64
    player_name = read_string(player_addr_name)

    en_name = convert_into_eng(player_name)
    write_string(player_addr_name, en_name)
    logger.info('Wrote player name ' + str(en_name))
    chdir(og_working_dir)
except Exception as e:
    with open('out.log', 'a+') as f:
        f.write(e)
    """

    return str(shellcode)
