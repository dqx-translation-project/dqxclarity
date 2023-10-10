from common.db_ops import sql_read, sql_write
from common.lib import encode_to_utf8
from common.memory import MemWriter
from common.translate import detect_lang, Translate
from json import dumps

import os
import sys


class Dialog:

    translator = Translate()
    region = translator.region_code
    writer = None

    def __init__(self, address, debug=False):
        if not Dialog.writer:
            Dialog.writer = MemWriter()
        if debug:
            self.address = address
        else:
            self.address = Dialog.writer.unpack_to_int(address)

        self.text = Dialog.writer.read_string(self.address)
        if detect_lang(self.text):
            db_result = self.__read_db(self.text)
            if db_result:
                Dialog.writer.write_string(self.address, text=db_result)
            else:
                translated_text = self.__translate(self.text)
                if translated_text:
                    self.__write_db(source_text=self.text, translated_text=translated_text)
                    Dialog.writer.write_string(self.address, text=translated_text)


    def __read_db(self, text: str):
        result = sql_read(text=text, table="dialog", language=Dialog.region)
        if result:
            return result
        return None


    def __write_db(self, source_text: str, translated_text: str):
        return sql_write(
            source_text=source_text,
            translated_text=translated_text,
            table="dialog",
            language=Dialog.region,
        )


    def __translate(self, text: str):
        translated_text = Dialog.translator.sanitize_and_translate(
            text=text,
            wrap_width=46
        )
        return translated_text


def translate_shellcode(esi_address: int) -> str:
    """Returns shellcode for the translate function hook.

    address: Where text can be modified to be fed to the screen
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
    from hooking.dialog import Dialog
    Dialog({esi_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return encode_to_utf8(shellcode).decode()
