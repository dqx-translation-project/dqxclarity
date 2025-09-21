from common.db_ops import sql_read, sql_write
from common.lib import setup_logging
from common.memory import MemWriter
from common.process import is_dqx_process_running
from common.signatures import walkthrough_pattern
from common.translate import detect_lang, Translator
from pymem.exception import MemoryReadError, WinAPIError

import re
import sys
import time


def loop_scan_for_walkthrough(ready_event):
    """Scans for the walkthrough address in an infinite loop and translates
    when found."""
    # configure logging. this function runs in multiprocessing, so it does not
    # have the same access to the main log handler.
    global log
    log = setup_logging()

    log.info("Will watch for walkthrough text.")
    translator = Translator()

    if ready_event:
        ready_event.set()

    try:
        writer = MemWriter()
        pattern = re.compile(walkthrough_pattern[0:49])  # 49 sliced characters == 16 bytes
        while True:
            if address := writer.pattern_scan(pattern=walkthrough_pattern, data_only=True):
                prev_text = ""
                while True:
                    # check if the address is still valid by validating the pattern.
                    # if not, we'll re-scan for it.
                    verify = writer.read_bytes(address, 16)
                    if not pattern.match(verify):
                        log.debug("Lost walkthrough pattern. Starting scan again.")
                        address = writer.pattern_scan(pattern=walkthrough_pattern)
                        break
                    if text := writer.read_string(address + 16):
                        if text != prev_text:
                            prev_text = text
                            if detect_lang(text):
                                result = sql_read(text=text, table="walkthrough")
                                if result:
                                    writer.write_string(address + 16, result)
                                else:
                                    translated_text = translator.translate(
                                        text=text,
                                        wrap_width=31,
                                        max_lines=3,
                                        add_brs=False
                                    )
                                    try:
                                        sql_write(
                                            source_text=text,
                                            translated_text=translated_text,
                                            table="walkthrough"
                                        )
                                        writer.write_string(address + 16, translated_text)
                                    except Exception:
                                        log.exception("Failed to write walkthrough.")
                        else:
                            time.sleep(1)
            else:
                time.sleep(1)
    except MemoryReadError as e:
        if not is_dqx_process_running():
            sys.exit(0)
        raise(e)
    except WinAPIError as e:
        if e.error_code == 299:
            pass
        elif e.error_code == 5:
            if not is_dqx_process_running():
                sys.exit(0)
            else:
                raise e
        else:
            raise e
    except Exception:
        if not is_dqx_process_running():
            sys.exit(0)
        else:
            log.exception("Problem was detected with the walkthrough scanner.")
            sys.exit(1)
