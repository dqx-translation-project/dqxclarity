from common.memory import MemWriter
from common.signatures import menu_ai_name_pattern, player_name_pattern
from common.translate import transliterate_player_name
from loguru import logger as log
from pymem.exception import MemoryReadError, WinAPIError

import traceback


def scan_for_player_names(players: dict) -> None:
    """Scans for player nameplates and transliterates the Japanese name.

    :param players: Dictionary of players to override transliteration.
    """
    writer = MemWriter()
    if addresses := writer.pattern_scan(pattern=player_name_pattern, return_multiple=True, use_regex=True, data_only=True):
        for address in addresses:
            player_name_address = address + 48  # len of player_name_pattern - 1
            try:
                ja_name = writer.read_string(player_name_address)
                en_name = players.get(ja_name)
                if not en_name:
                    en_name = transliterate_player_name(ja_name)
                if en_name != ja_name:
                    # we use a leading x04 byte here as the game assumes all names that start
                    # with an english letter are GMs.
                    reread = writer.read_string(player_name_address)
                    if ja_name == reread:
                        writer.write_string(player_name_address, "\x04" + en_name)
            except UnicodeDecodeError:
                continue
            except MemoryReadError:
                continue
            except WinAPIError as e:
                if e.error_code == 299:
                    continue
                else:
                    raise e
            except Exception:
                log.debug(f"Failed to write player name.\n{traceback.format_exc()}")
                continue

    writer.close()

def scan_for_menu_ai_names(players: dict):
    """Scans for party member names in the party member communications window.

    :param players: Dictionary of players to override transliteration.
    """
    writer = MemWriter()
    if addresses := writer.pattern_scan(pattern=menu_ai_name_pattern, return_multiple=True, data_only=True):
        for address in addresses:
            name_address = address + 57
            try:
                ja_name = writer.read_string(name_address)
                en_name = players.get(ja_name)
                if not en_name:
                    en_name = transliterate_player_name(ja_name)
                if en_name != ja_name:
                    writer.write_string(name_address, en_name)
            except UnicodeDecodeError:
                continue
            except MemoryReadError:
                continue
            except WinAPIError as e:
                if e.error_code == 299:
                    continue
                else:
                    raise e
            except Exception:
                log.debug(f"Failed to write name.\n{traceback.format_exc()}")
                continue
