from common.db_ops import generate_m00_dict, sql_read, sql_write
from common.errors import MemoryReadError
from common.lib import setup_logging
from common.memory import MemWriter
from common.process import is_dqx_process_running
from common.signatures import (
    comm_name_pattern,
    concierge_name_pattern,
    menu_ai_name_pattern,
    npc_monster_pattern,
    player_name_pattern,
    sibling_name_pattern,
    walkthrough_pattern,
)
from common.translate import detect_lang, Translator, transliterate_player_name
from loguru import logger as log
from pymem.exception import MemoryReadError, WinAPIError

import re
import sys
import time
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


def scan_for_comm_names():
    """Scans for player names in the communications window and transliterates
    the Japanese name."""
    writer = MemWriter()
    player_names = generate_m00_dict(files="'local_player_names'")
    comm_name_addresses = writer.pattern_scan(pattern=comm_name_pattern, use_regex=True, return_multiple=True, data_only=True)

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
            if npc_type == b"\xE0\x3D":
                data = "NPC"
            elif npc_type == b"\x40\x2A":
                data = "MONSTER"
            elif npc_type == b"\xC8\x2C":
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


def loop_scan_for_walkthrough():
    """Scans for the walkthrough address in an infinite loop and translates
    when found."""
    # configure logging. this function runs in multiprocessing, so it does not
    # have the same access to the main log handler.
    global log
    log = setup_logging()

    log.info("Will watch for walkthrough text.")
    translator = Translator()

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
        else:
            raise e
    except Exception:
        if not is_dqx_process_running():
            sys.exit(0)
        else:
            log.exception("Problem was detected with the walkthrough scanner.")
            sys.exit(1)


def run_scans(player_names=True, npc_names=True):
    """Run chosen scans.

    :param player_names: Run player name scans.
    :param npc_names: Run NPC name scans.
    :param communication_window: Run adhoc scans.
    """
    # configure logging. this function runs in multiprocessing, so it does not
    # have the same access to the main log handler.
    global log
    log = setup_logging()

    if player_names:
        log.info("Will watch and update player names.")
    if npc_names:
        log.info("Will watch and update NPCs.")

    monsters = generate_m00_dict(files="'monsters'")
    npcs = generate_m00_dict(files="'npcs', 'custom_npc_name_overrides', 'custom_concierge_mail_names', 'local_player_names', 'local_mytown_names'")
    players = generate_m00_dict(files="'custom_npc_name_overrides', 'local_player_names'")
    mytown_names = generate_m00_dict(files="'custom_concierge_mail_names', 'local_mytown_names'")

    while True:
        try:
            if player_names:
                scan_for_player_names(players)
                scan_for_menu_ai_names(players)
            if npc_names:
                scan_for_npc_names(monsters=monsters, npcs=npcs)
                scan_for_concierge_names(mytown_names)
        except UnicodeDecodeError:
            pass
        except MemoryReadError:
            continue
        except WinAPIError as e:
            if e.error_code == 299:  # memory page changed
                continue
            elif e.error_code == 5:  # game closed
                continue
            else:
                raise e
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception:
            if is_dqx_process_running():
                log.exception("An exception occurred. dqxclarity will exit.")
                sys.exit(1)
            else:
                sys.exit(0)
