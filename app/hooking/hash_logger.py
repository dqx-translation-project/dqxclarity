"""Hooks the start and end of the function. This logs the real game filenames
and computed hashes so that they can be found in the game's idx lookup tables
found in the game folder.

The function itself computes a CRC32-poly8 checksum of the filename,
which is then used to do the lookup in the idx.
"""
from common.lib import get_project_root
from common.memory_local import MemWriterLocal
from json import dumps
from pathlib import Path

import logging
import os
import sys


class HashLogger:
    writer = None
    logger = None

    def __init__(
        self,
        ecx_address: int,
        esp_address: int,
    ):
        if not HashLogger.writer:
            HashLogger.writer = MemWriterLocal()
        if not HashLogger.logger:
            HashLogger.logger = logging.getLogger("hashlog")
            logger = HashLogger.logger
            logger.setLevel(logging.INFO)

            log_file = Path(get_project_root("logs/hashlog.csv"))
            handler = logging.FileHandler(log_file, mode="a+", encoding="utf-8")

            handler.setFormatter(logging.Formatter("%(message)s"))

            logger.addHandler(handler)
            logger.propagate = False

            if not log_file.exists():
                with open(log_file, "a+") as f:
                    f.write("hash_type,hash_input,hash_output,")

        mem = HashLogger.writer

        esp = mem.read_uint32(address=esp_address, value=True)
        ecx = mem.read_uint32(address=ecx_address, value=True)

        data_type = mem.read_uint32(address=esp, value=True)

        if hex(data_type) == "0xffffffff":
            hash_type = "dir"
            esp24 = mem.read_uint32(address=esp + 0x24, value=True)
            filepath = mem.read_string(address=esp24)
            hash_input = "/".join(filepath.split("/")[:-1])  # get path without filename
        else:
            hash_type = "file"
            esp2c = mem.read_uint32(address=esp + 0x2C, value=True)
            filepath = mem.read_string(address=esp2c)
            hash_input = filepath.rsplit("/", 1)[-1]  # just get filename

        hash_output = hex(ecx)

        # This appends the hash to the end of the existing hashlog,
        # which contains the hash value we're interested in.
        HashLogger.logger.info(f'"{hash_type}","{hash_input}",{hash_output}')


def hash_logger_shellcode(ecx_address: int, esp_address: int) -> str:
    """Returns shellcode to log hash values.

    :param ecx_address: Address of ecx that contains the hash value.
    :param esp_address: Address of esp for stack values.
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
    from hooking.hash_logger import HashLogger
    HashLogger({ecx_address}, {esp_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return shellcode


# unsigned int __cdecl sub_282CF0(char *a1, unsigned int a2)
# {
#   char *v2; // edx
#   unsigned int v4; // edi
#   unsigned int v5; // ecx
#   char v6; // bl
#   int v7; // eax
#   unsigned int v8; // esi
#   char v9; // bl
#   int v10; // eax
#   unsigned int v11; // ecx
#   char v12; // si
#   int v13; // eax
#   unsigned int v14; // ebx
#   char v15; // si
#   int v16; // eax
#   unsigned int v17; // ecx
#   char v18; // di
#   int v19; // eax
#   unsigned int v20; // esi
#   char v21; // cl
#   int v22; // eax
#   unsigned int v23; // edi
#   char v24; // cl
#   unsigned int v25; // esi
#   int v26; // eax
#   _BYTE *v27; // edi
#   unsigned int v28; // esi
#   char v29; // dl
#   int v30; // eax
#   bool v31; // zf
#   char v32; // bl
#   int v33; // eax
#   unsigned int v34; // [esp+8h] [ebp+8h]

#   v2 = a1;
#   if ( !a1 )
#     return 0;
#   v4 = a2;
#   v5 = -1;
#   if ( a2 >= 8 )
#   {
#     v34 = a2 >> 3;
#     do
#     {
#       v6 = *v2;
#       if ( (unsigned __int8)(*v2 - 65) > 0x19u )
#         v7 = (unsigned __int8)(v5 ^ v6);
#       else
#         v7 = (unsigned __int8)(v5 ^ (v6 + 32));
#       v8 = dword_10BC328[v7] ^ (v5 >> 8);
#       v9 = v2[1];
#       if ( (unsigned __int8)(v9 - 65) > 0x19u )
#         v10 = (unsigned __int8)(v8 ^ v9);
#       else
#         v10 = (unsigned __int8)(v8 ^ (v9 + 32));
#       v11 = dword_10BC328[v10] ^ (v8 >> 8);
#       v12 = v2[2];
#       if ( (unsigned __int8)(v12 - 65) > 0x19u )
#         v13 = (unsigned __int8)(v12 ^ v11);
#       else
#         v13 = (unsigned __int8)(v11 ^ (v12 + 32));
#       v14 = dword_10BC328[v13] ^ (v11 >> 8);
#       v15 = v2[3];
#       if ( (unsigned __int8)(v15 - 65) > 0x19u )
#         v16 = (unsigned __int8)(v15 ^ v14);
#       else
#         v16 = (unsigned __int8)(v14 ^ (v15 + 32));
#       v17 = dword_10BC328[v16] ^ (v14 >> 8);
#       v18 = v2[4];
#       if ( (unsigned __int8)(v18 - 65) > 0x19u )
#         v19 = (unsigned __int8)(v18 ^ v17);
#       else
#         v19 = (unsigned __int8)(v17 ^ (v18 + 32));
#       v20 = dword_10BC328[v19] ^ (v17 >> 8);
#       v21 = v2[5];
#       if ( (unsigned __int8)(v21 - 65) > 0x19u )
#         v22 = (unsigned __int8)(v20 ^ v21);
#       else
#         v22 = (unsigned __int8)(v20 ^ (v21 + 32));
#       v23 = dword_10BC328[v22] ^ (v20 >> 8);
#       v24 = v2[6];
#       v25 = v23 >> 8;
#       if ( (unsigned __int8)(v24 - 65) > 0x19u )
#         v26 = (unsigned __int8)(v23 ^ v24);
#       else
#         v26 = (unsigned __int8)(v23 ^ (v24 + 32));
#       v27 = v2 + 7;
#       v28 = dword_10BC328[v26] ^ v25;
#       v29 = v2[7];
#       if ( (unsigned __int8)(v29 - 65) > 0x19u )
#         v30 = (unsigned __int8)(v28 ^ v29);
#       else
#         v30 = (unsigned __int8)(v28 ^ (v29 + 32));
#       v2 = v27 + 1;
#       v5 = dword_10BC328[v30] ^ (v28 >> 8);
#       v4 = a2 - 8;
#       v31 = v34-- == 1;
#       a2 -= 8;
#     }
#     while ( !v31 );
#   }
#   for ( ; v4; --v4 )
#   {
#     v32 = *v2;
#     if ( (unsigned __int8)(*v2 - 65) > 0x19u )
#       v33 = (unsigned __int8)(v5 ^ v32);
#     else
#       v33 = (unsigned __int8)(v5 ^ (v32 + 32));
#     v5 = dword_10BC328[v33] ^ (v5 >> 8);
#     ++v2;
#   }
#   return v5;
# }

# python equivalent via chatgpt

# from __future__ import annotations

# from typing import Union


# def crc32_table_reflected(poly: int = 0xEDB88320) -> list[int]:
#     """
#     Generate the 256-entry reflected CRC-32 table for the given polynomial.
#     The common CRC-32/IEEE reflected poly is 0xEDB88320.
#     """
#     table = []
#     for i in range(256):
#         crc = i
#         for _ in range(8):
#             if crc & 1:
#                 crc = (crc >> 1) ^ poly
#             else:
#                 crc >>= 1
#         table.append(crc & 0xFFFFFFFF)
#     return table


# # This matches the typical dword_10BC328 layout for reflected CRC-32/IEEE.
# _DWORD_10BC328 = crc32_table_reflected(0xEDB88320)


# def ida_crc32_poly8_casefold(buf: Union[bytes, bytearray, memoryview, str], length: int | None = None) -> int:
#     """
#     Python version of your IDA function:

#     - init crc = 0xFFFFFFFF
#     - for each byte:
#         if 'A'..'Z': byte += 0x20 (ASCII lowercase)
#         crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
#     - returns crc (NO final xor)
#     """
#     if buf is None:
#         return 0

#     if isinstance(buf, str):
#         # IDA code is byte-oriented; filenames/paths are typically ASCII/UTF-8 bytes.
#         # Using UTF-8 is usually the safest assumption if you have non-ASCII.
#         data = buf.encode("utf-8")
#     else:
#         data = bytes(buf)

#     if length is None:
#         length = len(data)
#     else:
#         length = min(length, len(data))

#     crc = 0xFFFFFFFF

#     for b in data[:length]:
#         # ASCII uppercase A..Z => lowercase
#         if 0x41 <= b <= 0x5A:
#             b += 0x20
#         crc = _DWORD_10BC328[(crc ^ b) & 0xFF] ^ (crc >> 8)

#     return crc & 0xFFFFFFFF


# def ida_crc32_to_standard_crc32(ida_value: int) -> int:
#     """
#     If you want the *standard* CRC-32/IEEE output (xorout=0xFFFFFFFF),
#     this converts the IDA-function return value to the standard one.
#     """
#     return (ida_value ^ 0xFFFFFFFF) & 0xFFFFFFFF
