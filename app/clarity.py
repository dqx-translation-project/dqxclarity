from common.db_ops import sql_read, sql_write
from common.lib import get_abs_path, is_dqx_process_running, merge_jsons
from common.memory import pattern_scan, read_bytes, read_string, write_string
from common.signatures import (
    comm_name_pattern_1,
    comm_name_pattern_2,
    concierge_name_pattern,
    menu_ai_name_pattern,
    npc_monster_pattern,
    player_name_pattern,
    sibling_name_pattern,
    walkthrough_pattern,
)
from common.translate import convert_into_eng, detect_lang, Translate
from loguru import logger

import re
import sys
import time
import traceback


def scan_for_player_names():
    """Scans for addresses that are related to a specific pattern to translate
    player names."""
    if addresses := pattern_scan(pattern=player_name_pattern, return_multiple=True):
        for address in addresses:
            player_name_address = address + 48  # len of player_name_pattern - 1
            try:
                ja_name = read_string(player_name_address)
                en_name = convert_into_eng(ja_name)
                if en_name != ja_name:
                    # we use a leading x04 byte here as the game assumes all names that start
                    # with an english letter are GMs.
                    write_string(player_name_address, "\x04" + en_name)
            except UnicodeDecodeError:
                continue
            except Exception:
                logger.debug(f"Failed to write player name.\n{traceback.format_exc()}")
                continue


def scan_for_comm_names():
    """Scans for addresses that are related to a specific pattern to translate
    player names in the comms window."""
    comm_addresses = []

    # the comm names were found to use two patterns. the first set we can use as is, the second set
    # we need to jump ahead one byte before we r/w.
    comm_names_1 = pattern_scan(pattern=comm_name_pattern_1, use_regex=True, return_multiple=True)
    comm_names_2 = pattern_scan(pattern=comm_name_pattern_2, use_regex=True, return_multiple=True)

    for address in comm_names_1:
        comm_addresses.append(address)

    for address in comm_names_2:
        comm_addresses.append(address + 1)

    for address in comm_addresses:
        try:
            ja_name = read_string(address)
            en_name = convert_into_eng(ja_name)
            if en_name != ja_name:
                write_string(address, "\x04" + en_name)
        except UnicodeDecodeError:
            continue
        except TypeError:
            continue
        except Exception:
            logger.debug(f"Failed to write name.\n{traceback.format_exc()}")
            continue


def scan_for_sibling_name():
    """Scans for addresses that are related to a specific pattern to translate
    the player's sibling name."""
    if address := pattern_scan(pattern=sibling_name_pattern):
        sibling_address = address + 51  # len of num of (sibling_name_pattern - 1)
        player_address = address - 21  # start of sibling_name_pattern - 21 (jump to player name)
        try:
            ja_sibling_name = read_string(sibling_address)
            ja_player_name = read_string(player_address)

            en_sibling_name = convert_into_eng(ja_sibling_name)
            en_player_name = convert_into_eng(ja_player_name)

            if en_sibling_name != ja_sibling_name:
                write_string(sibling_address, "\x04" + en_sibling_name)

            if en_player_name != ja_player_name:
                write_string(player_address, "\x04" + en_player_name)
        except UnicodeDecodeError:
            pass
        except Exception:
            logger.debug(f"Failed to write name.\n{traceback.format_exc()}")


def scan_for_concierge_names():
    """Scans for addresses that are related to a specific pattern to translate
    concierge names."""
    if addresses := pattern_scan(pattern=concierge_name_pattern, return_multiple=True):
        for address in addresses:
            name_address = address + 12  # jump to name
            try:
                ja_name = read_string(name_address)
                en_name = convert_into_eng(ja_name)
                if en_name != ja_name:
                    write_string(name_address, "\x04" + en_name)
            except UnicodeDecodeError:
                pass
            except Exception:
                logger.debug(f"Failed to write name.\n{traceback.format_exc()}")
                continue


def scan_for_npc_names():
    """Scan to look for NPC names, monster names and names above your party
    member's heads and translates them into English."""
    misc_files = "/".join([get_abs_path(__file__), "misc_files"])
    translated_npc_names = merge_jsons([
        f"{misc_files}/smldt_msg_pkg_NPC_DB.win32.json",
        f"{misc_files}/custom_npc_names.json"
    ])
    translated_monster_names = merge_jsons([f"{misc_files}/subPackage02Client.win32.json"])

    if npc_list := pattern_scan(pattern=npc_monster_pattern, return_multiple=True):
        for address in npc_list:
            npc_type = read_bytes(address + 36, 2)
            if npc_type == b"\xBC\x71":
                data = "NPC"
                translated_names = translated_npc_names
            elif npc_type == b"\x6C\x5F":
                data = "MONSTER"
                translated_names = translated_monster_names
            elif npc_type == b"\xD4\x61":
                data = "AI_NAME"
            else:
                continue

            name_addr = address + 48  # jump to name
            name = read_string(name_addr)

            if data == "NPC" or data == "MONSTER":
                if name in translated_names:
                    value = translated_names.get(name)
                    if value:
                        try:
                            write_string(name_addr, value)
                        except Exception as e:
                            logger.debug(f"Failed to write {data}. {e}")
            elif data == "AI_NAME":
                en_name = convert_into_eng(name)
                if en_name != name:
                    try:
                        write_string(name_addr, "\x04" + en_name)
                    except Exception as e:
                        logger.debug(f"Failed to write {data}. {e}")


def scan_for_menu_ai_names():
    """Scans for addresses that are related to a specific pattern to translate
    party member names in the party member panel."""
    if addresses := pattern_scan(pattern=menu_ai_name_pattern, return_multiple=True):
        for address in addresses:
            name_address = address + 57
            try:
                ja_name = read_string(name_address)
                en_name = convert_into_eng(ja_name)
                if en_name != ja_name:
                    write_string(name_address, en_name)
            except UnicodeDecodeError:
                pass
            except Exception:
                logger.debug(f"Failed to write name.\n{traceback.format_exc()}")
                continue


def loop_scan_for_walkthrough():
    """Scans for the walkthrough address in an infinite loop and translates
    when found."""
    logger.info("Will watch for walkthrough text.")
    translator = Translate()

    try:
        pattern = re.compile(walkthrough_pattern[0:55])  # 55 sliced characters == 16 bytes
        while True:
            if address := pattern_scan(pattern=walkthrough_pattern):
                prev_text = ""
                while True:
                    # check if the address is still valid by validating the pattern.
                    # if not, we'll re-scan for it.
                    verify = read_bytes(address, 16)
                    if not pattern.match(verify):
                        logger.debug("Lost walkthrough pattern. Starting scan again.")
                        break
                    if text := read_string(address + 16):
                        if text != prev_text:
                            prev_text = text
                            if detect_lang(text):
                                result = sql_read(text=text, table="walkthrough", language=translator.region_code)
                                if result:
                                    write_string(address + 16, result)
                                else:
                                    translated_text = translator.sanitize_and_translate(
                                        text=text,
                                        wrap_width=31,
                                        max_lines=3,
                                        add_brs=False
                                    )
                                    try:
                                        sql_write(
                                            source_text=text,
                                            translated_text=translated_text,
                                            table="walkthrough",
                                            language=translator.region_code
                                        )
                                        write_string(address + 16, translated_text)
                                    except Exception:
                                        logger.exception("Failed to write walkthrough.")
                        else:
                            time.sleep(1)
            else:
                time.sleep(1)
    except Exception:
        if not is_dqx_process_running():
            logger.exception("A problem with the walkthrough scanner was detected.")
            sys.exit(1)
        else:
            logger.exception("Problem detected running walkthrough scanner.")


def run_scans(player_names=True, npc_names=True, debug=False):
    """Run chosen scans.

    :param player_names: Run player name scans.
    :param npc_names: Run NPC name scans.
    :param communication_window: Run adhoc scans.
    """
    if player_names:
        logger.info("Will watch and update player names.")
    if npc_names:
        logger.info("Will watch and update NPCs.")

    while True:
        try:
            if player_names:
                scan_for_player_names()
                scan_for_menu_ai_names()
            if npc_names:
                scan_for_npc_names()
                scan_for_concierge_names()
        except UnicodeDecodeError:
            pass
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception as e:
            if is_dqx_process_running():
                logger.exception("An exception occurred. dqxclarity will exit.")
                sys.exit(1)
            else:
                logger.info("DQX has been closed. Exiting.")
                sys.exit(0)
