import re
import sys
import time
from loguru import logger
import pymem

from common.translate import (
    sqlite_read,
    sqlite_write,
    detect_lang,
    determine_translation_service,
    sanitized_dialog_translate,
    convert_into_eng,
)

from common.memory import (
    read_bytes,
    read_string,
    write_string,
    pattern_scan,
)

from common.signatures import (
    npc_monster_pattern,
    concierge_name_pattern,
    menu_ai_name_pattern,
    player_name_pattern,
    sibling_name_pattern,
    walkthrough_pattern,
    comm_name_pattern_1,
    comm_name_pattern_2
)

from common.lib import merge_jsons, get_abs_path


def scan_for_player_names():
    """
    Scans for addresses that are related to a specific
    pattern to translate player names.
    """
    if player_list := pattern_scan(pattern=player_name_pattern, return_multiple=True):
        for address in player_list:
            player_name_address = address + 48  # len of num of (player_name_pattern - 1)
            try:
                ja_player_name = read_string(player_name_address)
                romaji_name = convert_into_eng(ja_player_name)
                if romaji_name != ja_player_name:
                    write_string(player_name_address, "\x04" + romaji_name)
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.debug(f"Failed to write player name at {str(hex(address))} for name {romaji_name}.")


def scan_for_comm_names():
    """
    Scans for addresses that are related to a specific
    pattern to translate player names in the comms window.
    """
    comm_name_list_1 = pattern_scan(pattern=comm_name_pattern_1, use_regex=True, return_multiple=True)
    comm_name_list_2 = pattern_scan(pattern=comm_name_pattern_2, use_regex=True, return_multiple=True)
    comm_name_list_2_mod = []
    for address in comm_name_list_2:
        comm_name_list_2_mod.append(address + 1)
    comm_names = comm_name_list_1 + comm_name_list_2_mod
    for address in comm_names:
        try:
            ja_name = read_string(address)
            romaji_name = convert_into_eng(ja_name)
            if romaji_name != ja_name:
                write_string(address, "\x04" + romaji_name)
        except UnicodeDecodeError:
            continue
        except Exception as e:
            logger.debug(f"Failed to write comms name at {str(hex(address))} for name {romaji_name}.")


def scan_for_sibling_names():
    """
    Scans for addresses that are related to a specific
    pattern to translate sibling names.
    """
    if address := pattern_scan(pattern=sibling_name_pattern):
        sibling_name_address = address + 51  # len of num of (sibling_name_pattern - 1)
        player_name_address = address - 21 # Start of sibling_name_pattern - 21 (jump to player name)
        try:
            ja_sibling_name = read_string(sibling_name_address)
            ja_player_name = read_string(player_name_address)
            romaji_sibling_name = convert_into_eng(ja_sibling_name)
            romaji_player_name = convert_into_eng(ja_player_name)
            if romaji_sibling_name != ja_sibling_name:
                write_string(sibling_name_address, "\x04" + romaji_sibling_name)
                logger.debug(f"Wrote sibling name at {str(hex(address))} for name {romaji_sibling_name}.")
            if romaji_player_name != ja_player_name:
                write_string(player_name_address, "\x04" + romaji_player_name)
                logger.debug(f"Wrote player name at {str(hex(address))} for name {romaji_player_name}.")
        except UnicodeDecodeError:
            logger.debug(f"UnicodeDecodeError: Failed to write sibling name at {str(hex(address))} for name {romaji_sibling_name}.")
        except Exception as e:
            logger.debug(f"Failed to write sibling name at {str(hex(address))} for name {romaji_sibling_name}.")


def scan_for_concierge_names():
    if concierge_names := pattern_scan(pattern=concierge_name_pattern, return_multiple=True):
        for address in concierge_names:
            name_addr = address + 12  # jump to name
            try:
                ja_name = read_string(name_addr)
                en_name = convert_into_eng(ja_name)
                if en_name != ja_name:
                    write_string(name_addr, "\x04" + en_name)
                    logger.debug(f"Wrote player name at {str(hex(address))} for name {en_name}.")
            except UnicodeDecodeError:
                pass


def scan_for_npc_names():
    """
    Scan to look for NPC and monster names and translate them into English.
    Also finds names above your party members.
    """
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
                            logger.debug(f"Wrote NPC name at {str(hex(address))} for name {value}.")
                        except Exception as e:
                            logger.debug(f"Failed to write {data} at {str(hex(address))} for name {value}.")
            elif data == "AI_NAME":
                en_name = convert_into_eng(name)
                if en_name != name:
                    try:
                        write_string(name_addr, "\x04" + en_name)
                        logger.debug(f"Wrote AI name at {str(hex(address))} for name {en_name}.")
                    except Exception as e:
                        logger.debug(f"Failed to write {data} at {str(hex(address))} for name {en_name}.")


def scan_for_menu_ai_names():
    """
    Scans for the walkthrough address and translates when found, then translates party members.
    """
    if ai_list := pattern_scan(pattern=menu_ai_name_pattern, return_multiple=True):
        for address in ai_list:
            ai_name_address = address + 57
            if ja_ai_name := read_string(ai_name_address):
                romaji_name = convert_into_eng(ja_ai_name)
                if romaji_name != ja_ai_name:
                    try:
                        write_string(ai_name_address, romaji_name)
                        logger.debug(f"Wrote party member name at {str(hex(address))} for name {romaji_name}.")
                    except Exception as e:
                        logger.debug(f"Failed to write party member name at {str(hex(address))} for name {romaji_name}.")


def loop_scan_for_walkthrough():
    """
    Scans for the walkthrough address in an infinite loop and translates when found.
    """
    api_details = determine_translation_service()
    logger.info("Will watch for walkthrough text.")

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
                                result = sqlite_read(text, "en", "walkthrough")
                                if result:
                                    write_string(address + 16, result)
                                else:
                                    translated_text = sanitized_dialog_translate(
                                        text,
                                        text_width=31,
                                        max_lines=3,
                                    )
                                    try:
                                        sqlite_write(text, "walkthrough", translated_text, api_details["RegionCode"])
                                        write_string(address + 16, translated_text)
                                        logger.debug("Wrote walkthrough.")
                                    except Exception as e:
                                        logger.debug(f"Failed to write walkthrough text at {str(hex(address))}.")
                        else:
                            time.sleep(1)
            else:
                time.sleep(1)
    except TypeError:
        logger.error(f"Cannot find DQXGame.exe process. dqxclarity will exit.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Exception occurred:\n\n{e}")
        sys.exit(1)


def run_scans(player_names=True, npc_names=True, debug=False):
    """
    Run chosen scans.

    :param player_names: Run player name scans.
    :param npc_names: Run NPC name scans.
    :param communication_window: Run adhoc scans.
    """
    logger.remove()
    if debug:
        logger.add(sys.stderr, level="DEBUG")
    else:
        logger.add(sys.stderr, level="INFO")
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
        except TypeError:
            logger.error(f"Cannot find DQXGame.exe process. dqxclarity will exit.")
            sys.exit(1)
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception as e:
            logger.error(f"Exception occurred:\n\n{e}")
            sys.exit(1)
