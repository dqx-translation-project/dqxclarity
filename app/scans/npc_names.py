from common.memory import MemWriter
from common.signatures import concierge_name_pattern, npc_monster_pattern
from common.translate import transliterate_player_name
from loguru import logger as log
from pymem.exception import MemoryReadError, WinAPIError

import traceback


def scan_for_npc_names(monsters: dict, npcs: dict):
    """Scans for NPC names, monster names and names above your party member's
    heads and converts their Japanese names to English.

    :monsters players: Dictionary of monster names to look up. No
    transliteration is done     if there's no match. :npcs players:
    Dictionary of npcs to override transliteration.
    """
    writer = MemWriter()

    if npc_list := writer.pattern_scan(pattern=npc_monster_pattern, return_multiple=True, data_only=True):
        for address in npc_list:
            npc_type = writer.read_bytes(address + 36, 2)
            if npc_type == b"\x54\x27":
                data = "NPC"
            elif npc_type == b"\x8C\x13":
                data = "MONSTER"
            elif npc_type == b"\x20\x16":
                data = "AI_NAME"
            else:
                continue

            name_addr = address + 48  # jump to name
            name = writer.read_string(name_addr)

            if data == "NPC":
                if value := npcs.get(name):
                    try:
                        reread = writer.read_string(name_addr)
                        if reread == name:
                            writer.write_string(name_addr, value)
                    except Exception as e:
                        log.debug(f"Failed to write {data}. {e}")
            elif data == "MONSTER":
                if value := monsters.get(name):
                    try:
                        reread = writer.read_string(name_addr)
                        if reread == name:
                            writer.write_string(name_addr, value)
                    except Exception as e:
                        log.debug(f"Failed to write {data}. {e}")
            elif data == "AI_NAME":
                en_name = npcs.get(name)
                if not en_name:
                    en_name = transliterate_player_name(name)
                if en_name != name:
                    try:
                        reread = writer.read_string(name_addr)
                        if reread == name:
                            writer.write_string(name_addr, "\x04" + en_name)
                    except Exception as e:
                        log.debug(f"Failed to write {data}. {e}")

    writer.close()


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
