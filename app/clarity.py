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
    write_bytes,
    pattern_scan,
)

from common.signatures import (
    npc_monster_pattern,
    concierge_name_pattern,
    menu_ai_name_pattern,
    player_name_pattern,
    sibling_name_pattern,
    walkthrough_pattern,
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
                    write_bytes(player_name_address, b"\x04" + romaji_name.encode("utf-8") + b"\x00")
            except UnicodeDecodeError:
                continue
            except pymem.exception.WinAPIError as e:
                if "error_code: 299" in str(e):  # impartial read, just ignore.
                    continue
                else:
                    raise
            except Exception as e:
                logger.debug(f"Failed to write player name at {str(hex(address))} for name {romaji_name}.")


def scan_for_sibling_names():
    """
    Scans for addresses that are related to a specific
    pattern to translate sibling names.
    """
    if sibling_list := pattern_scan(pattern=sibling_name_pattern, return_multiple=True):
        for address in sibling_list:
            sibling_name_address = address + 51  # len of num of (sibling_name_pattern - 1)
            try:
                ja_sibling_name = read_string(sibling_name_address)
                romaji_name = convert_into_eng(ja_sibling_name)
                if romaji_name != ja_sibling_name:
                    write_bytes(sibling_name_address, b"\x04" + romaji_name.encode("utf-8") + b"\x00")
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.debug(f"Failed to write sibling name at {str(hex(address))} for name {romaji_name}.")

        
def scan_for_concierge_names():
    if concierge_names := pattern_scan(pattern=concierge_name_pattern, return_multiple=True):
        for address in concierge_names:
            name_addr = address + 12  # jump to name
            try:
                ja_name = read_string(name_addr)
                en_name = convert_into_eng(ja_name)
                if en_name != ja_name:
                    write_bytes(name_addr, b"\x04" + str.encode(en_name) + b"\x00")
            except UnicodeDecodeError:
                logger.debug(f"Failed to write concierge name at {str(hex(address))} for name {en_name}.")
                pass


def scan_for_npc_names():
    """
    Scan to look for NPC and monster names and translate them into English.
    Also finds names above your party members.
    """
    misc_files = "/".join([get_abs_path(__file__), "misc_files"])
    translated_names = merge_jsons([
        f"{misc_files}/subPackage02Client.win32.json",
        f"{misc_files}/smldt_msg_pkg_NPC_DB.win32.json",
        f"{misc_files}/custom_npc_names.json"
    ])

    if npc_list := pattern_scan(pattern=npc_monster_pattern, return_multiple=True):
        for address in npc_list:
            npc_type = read_bytes(address + 36, 2)
            if npc_type == b"\x34\xE5" or npc_type == b"\x7C\xD2":
                data = "NPC"
            elif npc_type == b"\xE4\xD4":
                data = "AI_NAME"
            else:
                continue

            name_addr = address + 48  # jump to name
            name = read_string(name_addr)

            if data == "NPC":
                if name in translated_names:
                    value = translated_names.get(name)
                    if value:
                        try:
                            write_string(name_addr, value)
                        except Exception as e:
                            logger.warning(f"Failed to write {data} name {value}.")
            elif data == "AI_NAME":
                en_name = convert_into_eng(name)
                if en_name != name:
                    try:
                        write_bytes(name_addr, b"\x04" + en_name.encode("utf-8") + b"\x00")
                    except Exception as e:
                        logger.warning(f"Failed to write {data} for {en_name}.")


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
                        logger.debug(f"Wrote player name {romaji_name}.")
                    except Exception as e:
                        logger.debug(f"Failed to write Menu AI name at {str(hex(address))} for name {romaji_name}.")


def loop_scan_for_walkthrough():
    """
    Scans for the walkthrough address in an infinite loop and translates when found.
    """
    api_details = determine_translation_service()
    logger.info("Will watch for walkthrough text.")

    while True:
        if address := pattern_scan(pattern=walkthrough_pattern):
            prev_text = ""
            while True:
                if text := read_string(address + 16):
                    if text != prev_text:
                        prev_text = text
                        if detect_lang(text):
                            result = sqlite_read(text, "en", "walkthrough")
                            if result:
                                write_string(address + 16, result)
                            else:
                                translated_text = sanitized_dialog_translate(
                                    api_details["TranslateService"],
                                    text,
                                    api_details["TranslateKey"],
                                    api_details["RegionCode"],
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
                        time.sleep(5)
        else:
            time.sleep(0.5)


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
        except pymem.exception.WinAPIError as e:
            if "error_code: 299" in str(e):
                logger.debug("WinApi error 299: Impartial read. Ignoring.")
                continue
            elif "error_code: 5" in str(e):  # ERROR_ACCESS_DENIED. *usually* means the game client was closed
                logger.error(f"Cannot find DQXGame.exe process. dqxclarity will exit.")
                sys.exit(1)
            else:
                raise
        except UnicodeDecodeError:
            pass
        except TypeError:
            logger.error(f"Cannot find DQXGame.exe process. dqxclarity will exit.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Exception occurred:\n\n{e}")
            sys.exit(1)
