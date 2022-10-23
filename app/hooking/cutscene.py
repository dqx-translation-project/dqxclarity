import sys
import os
from json import dumps


def cutscene_shellcode(edi_address: str) -> str:
    """
    Returns shellcode for the cutscene file dump function hook.

    :param edi_address: Where adhoc text for cutscene can be found.
    """
    local_paths = dumps(sys.path).replace("\\", "\\\\")
    working_dir = dumps(os.getcwd()).replace("\\", "\\\\")

    shellcode = rf"""
try:
    import sys
    from os import chdir, getcwd

    local_paths = {local_paths}
    working_dir = {working_dir}

    sys.path = local_paths
    og_working_dir = getcwd()
    chdir(working_dir)

    from clarity import write_adhoc_entry
    from common.lib import setup_logger
    from common.memory import read_bytes, write_bytes, scan_backwards, unpack_to_int
    from common.signatures import index_pattern

    logger = setup_logger('out', 'out.log')

    # get address values where text can be identified
    ja_address = unpack_to_int({edi_address})
    logger.info('Cutscene address found @ ' + str(hex(ja_address)))
    adhoc_address = scan_backwards(ja_address, index_pattern)
    if read_bytes(adhoc_address - 2, 1) != b'\x69':
        adhoc_bytes = read_bytes(adhoc_address, 64)
        adhoc_write = write_adhoc_entry(adhoc_address, str(adhoc_bytes.hex()))
        if adhoc_write['success']:
            logger.debug('Wrote cutscene file (' + str(adhoc_write['file']) + ')')
        elif adhoc_write['file'] is not None:
            logger.debug('New cutscene file. Will write to new_adhoc_dumps if it does not already exist.')
        elif adhoc_write['file'] is None:
            logger.debug('This file already exists in new_adhoc_dumps. Needs merge into github.')
        write_bytes(adhoc_address - 2, b'\x69')  # write our state byte so we know we already wrote this. nice.

    chdir(og_working_dir)
except Exception as e:
    with open('out.log', 'a+') as f:
        f.write(e)
    """

    return str(shellcode)
