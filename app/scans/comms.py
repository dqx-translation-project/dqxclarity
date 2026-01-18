import traceback
from common.db_ops import generate_m00_dict
from common.memory import MemWriter
from common.signatures import comm_name_pattern
from common.translate import transliterate_player_name
from loguru import logger as log
from pymem.exception import MemoryReadError, WinAPIError


def scan_for_comm_names():
    """Scans for player names in the communications window and transliterates
    the Japanese name."""
    writer = MemWriter()
    player_names = generate_m00_dict(files="'local_player_names'")
    comm_name_addresses = writer.pattern_scan(
        pattern=comm_name_pattern, use_regex=True, return_multiple=True, data_only=True
    )

    for address in comm_name_addresses:
        try:
            ja_name = writer.read_string(address)
            en_name = player_names.get(ja_name)
            if not en_name:
                en_name = transliterate_player_name(ja_name)
            if en_name != ja_name:
                reread = writer.read_string(address)
                if ja_name == reread:
                    writer.write_string(address, "\x04" + en_name)
        except UnicodeDecodeError:
            continue
        except TypeError:
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
