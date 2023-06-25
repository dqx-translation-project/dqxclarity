import sys
import os
from json import dumps
from common.db_ops import sql_read, sql_write
from common.translate import Translate, detect_lang
from common.memory import unpack_to_int, read_string, write_string


class Dialog(object):

    translator = Translate()
    region = translator.region_code

    def __init__(self, address, debug=False):
        if debug:
            self.address = address
        else:
            self.address = unpack_to_int(address)

        self.text = read_string(self.address)
        if detect_lang(self.text):
            db_result = self.__read_db(self.text)
            if db_result:
                write_string(self.address, text=db_result)
            else:
                translated_text = self.__translate(self.text)
                if translated_text:
                    self.__write_db(source_text=self.text, translated_text=translated_text)
                    write_string(self.address, text=translated_text)


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
    """
    Returns shellcode for the translate function hook.
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

    return str(shellcode)
