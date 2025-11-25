from common.errors import MemoryReadError
from common.memory import MemWriter
from common.signatures import sibling_name_pattern
from common.translate import transliterate_player_name
from loguru import logger as log
from pymem.exception import WinAPIError

import traceback


def scan_for_sibling_name():
    """Scans the player and sibling names and transliterates their Japanese
    names.

    The result will have their names updated in the dialog windows (and
    other references.)
    """
    writer = MemWriter()
    if address := writer.pattern_scan(pattern=sibling_name_pattern, data_only=True):
        sibling_address = address + 51  # len of num of (sibling_name_pattern - 1)
        player_address = address - 21  # start of sibling_name_pattern - 21 (jump to player name)
        try:
            ja_sibling_name = writer.read_string(sibling_address)
            ja_player_name = writer.read_string(player_address)

            en_sibling_name = transliterate_player_name(ja_sibling_name)
            en_player_name = transliterate_player_name(ja_player_name)

            if en_sibling_name != ja_sibling_name:
                writer.write_string(sibling_address, "\x04" + en_sibling_name)

            if en_player_name != ja_player_name:
                writer.write_string(player_address, "\x04" + en_player_name)
        except UnicodeDecodeError:
            pass
        except MemoryReadError:
            pass
        except WinAPIError as e:
            if e.error_code == 299:
                pass
            else:
                raise e
        except Exception:
            log.debug(f"Failed to write name.\n{traceback.format_exc()}")

    writer.close()
