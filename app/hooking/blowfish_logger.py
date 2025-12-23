from common.lib import get_project_root
from common.memory_local import MemWriterLocal
from json import dumps
from pathlib import Path

import os
import sys


class BlowfishLogger:
    writer = None

    def __init__(self, esp_address: int):
        if not BlowfishLogger.writer:
            BlowfishLogger.writer = MemWriterLocal()

        mem = BlowfishLogger.writer

        # read function arguments
        esp = mem.read_uint32(address=esp_address, value=True)
        # arg_1 = mem.read_uint32(address=esp+0x4, value=True)  # not helpful, but keeping for clarity.
        arg_2 = mem.read_uint32(address=esp+0x8, value=True)
        arg_3 = esp+0xC
        arg_4 = mem.read_uint32(address=esp+0x10, value=True)

        # data_size: size of the actual contents being decrypted
        # blowfish_key: key used for file decryption
        # total_size: total size of the file being decrypted, including header
        # filename: name of the file being decrypted

        # data_size = mem.read_uint32(address=esp+0x4, value=True)
        blowfish_key = mem.read_string(address=arg_2)
        total_size = mem.read_uint32(address=arg_3, value=True)
        filename = mem.read_string(address=arg_4)

        log_file = Path(get_project_root("logs/blowfish_log.csv"))
        if not log_file.exists():
            with open(log_file, "a+") as f:
                f.write("filepath,file_size,blowfish_key,\n")

        with open(log_file, "a+") as f:
            f.write(f"\"{filename}\",{total_size},\"{blowfish_key}\"\n")


def blowfish_logger_shellcode(esp_address: int) -> str:
    """Returns shellcode to log blowfish keys.

    :param esp_address: Address of esp to read call arguments.
    """
    local_paths = dumps(sys.path).replace("\\", "\\\\")
    log_path = os.path.join(os.path.abspath('.'), 'logs\\console.log').replace("\\", "\\\\")

    # Overwriting the process's sys.path with the one outside of the process
    # is required to run our imports and function code. It's also necessary to
    # escape the slashes.
    shellcode = f"""
try:
    import sys
    import traceback
    sys.path = {local_paths}
    from hooking.blowfish_logger import BlowfishLogger
    BlowfishLogger({esp_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return shellcode
