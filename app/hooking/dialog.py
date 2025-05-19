from common.db_ops import init_db, search_bad_strings, sql_read
from common.memory import MemWriter
from common.translate import detect_lang, Translate
from json import dumps

import os
import sys


class Dialog:

    translator = Translate()
    writer = None

    def __init__(self, text_address: int, npc_address: int, debug=False):
        if not Dialog.writer:
            Dialog.writer = MemWriter()
        if debug:
            self.text_address = text_address
            self.npc_address = npc_address
        else:
            self.text_address = Dialog.writer.unpack_to_int(text_address)
            self.npc_address = Dialog.writer.unpack_to_int(npc_address)

        # npc name is on the stack, not directly in a register.
        self.npc_address = Dialog.writer.proc.read_long(self.npc_address + 0x14)

        self.text = Dialog.writer.read_string(self.text_address)
        self.npc_name = self.__get_npc_name()

        if detect_lang(self.text):
            bad_strings_result = self.__search_bad_strings_table(self.text)
            if bad_strings_result:
                Dialog.writer.write_string(self.text_address, text=bad_strings_result)
                return

            db_result = self.__read_db(self.text)
            if db_result:
                Dialog.writer.write_string(self.text_address, text=db_result)
                return

            self.translated_text = self.__translate(self.text)
            if self.translated_text:
                self.__write_db()
                Dialog.writer.write_string(self.text_address, text=self.translated_text)


    def __get_npc_name(self):
        try:
            npc_name = Dialog.writer.read_string(self.npc_address)
            if not npc_name:
                npc_name = "No_NPC"
        except:
            npc_name = "No_NPC"
        return npc_name


    def __read_db(self, text: str):
        result = sql_read(text=text, table="dialog")
        if result:
            return result
        return None


    def __write_db(self):
        try:
            conn, cursor = init_db()
            escaped_text = self.translated_text.replace("'", "''")
            select_query = f"SELECT ja FROM dialog WHERE ja = '{self.text}'"
            update_query = f"UPDATE dialog SET en = '{escaped_text}' WHERE ja = '{self.text}'"
            insert_query = f"INSERT INTO dialog (ja, npc_name, en) VALUES ('{self.text}', '{self.npc_name}', '{escaped_text}')"
            results = cursor.execute(select_query)

            if results.fetchone() is None:
                cursor.execute(insert_query)
            else:
                cursor.execute(update_query)

            conn.commit()
        finally:
            if conn:
                conn.close()


    def __translate(self, text: str):
        translated_text = Dialog.translator.sanitize_and_translate(
            text=text,
            wrap_width=46
        )
        return translated_text


    def __search_bad_strings_table(self, text: str):
        """Searches the bad_strings table. This is used to fix instances of
        text where machine translation completely screwed up the text and
        caused the game to have issues.

        :param text: String to search
        :returns: Returns either the English text or None if no match
            was found.
        """
        # use wildcard syntax as we want to match for BAD_STRING data.
        result = search_bad_strings(text)
        if result:
            return result

        return None


def translate_shellcode(esi_address: int, esp_address: int) -> str:
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
    Dialog({esi_address}, {esp_address})
except Exception as e:
    with open("{log_path}", "a+") as f:
        f.write(str(traceback.format_exc()))
    """

    return shellcode
