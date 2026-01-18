import traceback
from common.memory import MemWriter
from common.signatures import concierge_name_pattern
from common.translate import transliterate_player_name
from loguru import logger as log
from pymem.exception import MemoryReadError, WinAPIError


def scan_for_concierge_names(players: dict):
    """Scans for concierge NPCs and transliterates their Japanese names.

    :param players: Dictionary of players to override transliteration.
    """
    writer = MemWriter()
    if addresses := writer.pattern_scan(pattern=concierge_name_pattern, return_multiple=True, data_only=True):
        for address in addresses:
            name_address = address + 12  # jump to name
            try:
                ja_name = writer.read_string(name_address)
                en_name = players.get(ja_name)
                if not en_name:
                    en_name = transliterate_player_name(ja_name)
                if en_name != ja_name:
                    reread = writer.read_string(name_address)
                    if ja_name == reread:
                        writer.write_string(name_address, "\x04" + en_name)
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

    writer.close()
