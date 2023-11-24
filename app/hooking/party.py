from common.lib import encode_to_utf8, get_project_root, merge_jsons
from common.memory import MemWriter
from common.translate import convert_into_eng, detect_lang
from json import dumps

import os
import sys


class PartyMembers:

    writer = None
    player_names = None

    def __init__(self, address, debug=False):
        if not PartyMembers.writer:
            PartyMembers.writer = MemWriter()

        if not PartyMembers.player_names:
            PartyMembers.player_names = merge_jsons([
                get_project_root("misc_files/custom_player_names.json")
            ])

        if debug:
            self.address = address
        else:
            self.address = PartyMembers.writer.unpack_to_int(address=address)

        ja_name = self.__read_party_name()
        if not self.__is_name_japanese(name=ja_name):
            return

        en_name = self.__get_en_party_name(player_name=ja_name)
        self.__write_party_name(en_name)


    def __is_name_japanese(self, name: str):
        return detect_lang(text=name)


    def __read_party_name(self):
        return PartyMembers.writer.read_string(address=self.address + 104)


    def __get_en_party_name(self, player_name: str):
        if player_name in PartyMembers.player_names:
            return PartyMembers.player_names[player_name]

        return convert_into_eng(word=player_name)


    def __write_party_name(self, player_name: str):
        return PartyMembers.writer.write_string(address=self.address + 104, text=player_name)


def rename_party_members_shellcode(ebx_address: int) -> str:
    """Returns shellcode to rename party members into Romaji.

    ebx_address: Where text can be modified
    """
    local_paths = dumps(sys.path).replace("\\", "\\\\")
    log_path = os.path.join(os.path.abspath('.'), 'logs\\console.log').replace("\\", "\\\\")

    shellcode = rf"""
try:
    import sys
    import traceback
    sys.path = {local_paths}
    from hooking.party import PartyMembers
    PartyMembers({ebx_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return encode_to_utf8(shellcode).decode()
