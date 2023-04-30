from pathlib import Path
import sys
import time
import random
from evtxfile import EvtxFile
from alive_progress import alive_bar
from loguru import logger
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
    get_start_of_game_text,
    find_first_match,
)
from common.signatures import (
    evtx_pattern,
    index_pattern,
    foot_pattern,
    npc_monster_pattern,
    concierge_name_pattern,
    menu_ai_name_pattern,
    player_name_pattern,
    sibling_name_pattern,
    master_quest_pattern,
    walkthrough_pattern,
)
from common.lib import (
    split_hex_into_spaces,
    query_csv,
    generate_hex,
    write_file,
    read_json_file,
    merge_jsons,
    dump_game_file,
)


def write_initial_evtx():
    """Writes over the TEXT section of found EVTX files in memory."""
    evtx_list = pattern_scan(pattern=evtx_pattern, return_multiple=True)
    list_length = len(evtx_list)
    with alive_bar(list_length, title="Translating..", theme="musical", length=20) as progress_bar:
        for address in evtx_list:
            progress_bar()  # pylint: disable=not-callable
            evtx = EvtxFile(address)
            if not evtx.file:
                evtx.write_to_disk()


def write_adhoc_entry(start_addr: int, hex_str: str) -> dict:
    """
    Checks the stored json files for a matching adhoc file. If found,
    converts the json into bytes and writes bytes at the appropriate
    address.
    """
    results = {}
    hex_result = split_hex_into_spaces(hex_str)
    csv_result = query_csv(hex_result)
    if csv_result:
        file = csv_result["file"]
        if file:
            hex_to_write = generate_hex(file)
            index_address = find_first_match(start_addr, index_pattern)
            if index_address:
                text_address = get_start_of_game_text(index_address)
                if text_address:
                    write_bytes(text_address, hex_to_write)
                    results["success"] = True
                    results["file"] = file
                    return results
    else:
        results["success"] = False
        filename = str(random.randint(1, 1000000000))
        Path("new_adhoc_dumps/en").mkdir(parents=True, exist_ok=True)
        Path("new_adhoc_dumps/ja").mkdir(parents=True, exist_ok=True)

        csv_path = "new_adhoc_dumps/new_hex_dict.csv"
        new_csv = Path(csv_path)
        if new_csv.is_file():
            csv_result = query_csv(hex_result, csv_path)
            if csv_result:  # if we have an entry, don't make another one
                results["file"] = None
                return results
        else:
            write_file("new_adhoc_dumps", "new_hex_dict.csv", "a", "file,hex_string\n")

        # get number of bytes to read from start
        begin_address = get_start_of_game_text(start_addr)  # make sure we start on the first byte of the first letter
        end_address = find_first_match(begin_address, foot_pattern)
        bytes_to_read = end_address - begin_address

        # dump game file
        game_file = dump_game_file(begin_address, bytes_to_read)
        ja_data = game_file["ja"]
        en_data = game_file["en"]
        write_file("new_adhoc_dumps", "new_hex_dict.csv", "a", f"{filename},{hex_result}\n")
        write_file("new_adhoc_dumps/ja", f"{filename}.json", "w", ja_data)
        write_file("new_adhoc_dumps/en", f"{filename}.json", "w", en_data)
        results["file"] = filename
        return results
    return None


def scan_for_adhoc_files(debug=False):
    """
    Scans for specific adhoc files that have yet to have a hook written for them.

    :param api: Enable dialog insertion by working with the translation API.
    :param cutscenes: Whether to enable cutscene translation.
    """
    logger.remove()
    if debug:
        logger.add(sys.stderr, level="DEBUG")
    else:
        logger.add(sys.stderr, level="INFO")
    try:
        evtx_list = pattern_scan(pattern=evtx_pattern, return_multiple=True)
        for evtx_address in evtx_list:
            evtx = EvtxFile(evtx_address)
            if evtx.wrote:
                logger.debug(f"Wrote {evtx.file} @ {hex(evtx_address)}")
            else:
                if not evtx.file:
                    if evtx.write_to_disk():
                        logger.debug(f"Found new file. Check out the unknown_json folder.")
    except TypeError:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.")
    except Exception as e:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.\nError: {e}")
        sys.exit()


def scan_for_player_names():
    """
    Scans for addresses that are related to a specific
    pattern to translate player names.
    """
    try:
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
                except Exception as e:
                    logger.warning("INFO ONLY: Failed to write player name.")
    except TypeError:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.")
        sys.exit()
    except Exception as e:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.\nError: {e}")
        sys.exit()


def scan_for_sibling_names():
    """
    Scans for addresses that are related to a specific
    pattern to translate sibling names.
    """
    try:
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
                    logger.warning("INFO ONLY: Failed to write sibling name.")
    except TypeError:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.")
        sys.exit()
    except Exception as e:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.\nError: {e}")
        sys.exit()
        
        
def scan_for_concierge_names():
    try:
        if concierge_names := pattern_scan(pattern=concierge_name_pattern, return_multiple=True):
            for address in concierge_names:
                name_addr = address + 12  # jump to name
                try:
                    ja_name = read_string(name_addr)
                    en_name = convert_into_eng(ja_name)
                    if en_name != ja_name:
                        write_bytes(name_addr, b"\x04" + str.encode(en_name) + b"\x00")
                except UnicodeDecodeError:
                    pass
    except TypeError:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.")
        sys.exit()
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit()


def scan_for_npc_names():
    """
    Scan to look for NPC and monster names and translate them into English.
    Also finds names above your party members.
    """
    translated_names = merge_jsons(
        ["json/_lang/en/monsters.json", "json/_lang/en/npc_names.json", "json/_lang/en/custom_npc_names.json"]
    )

    try:
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
    except TypeError:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.")
        sys.exit()
    except Exception as e:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.\nError: {e}")
        sys.exit()


def scan_for_menu_ai_names():
    """
    Scans for the walkthrough address and translates when found, then translates party members.
    """
    try:
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
                            logger.warning("INFO ONLY: Failed to write Menu AI name.")
    except UnicodeDecodeError:
        pass
    except TypeError:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.")
        sys.exit()
    except Exception as e:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.\nError {e}")
        sys.exit()


def scan_for_master_quests():
    """
    Scans for master quest addresses and translates when found.
    """
    master_data = read_json_file("json/_lang/en/custom_master_quests.json")

    try:
        master_list = pattern_scan(pattern=master_quest_pattern, return_multiple=True)

        if master_list != []:
            for address in master_list:
                master_address = address + 12
                try:
                    master_name = read_string(master_address)
                    num_bytes_to_read = len(master_name.encode("utf-8"))
                    master_name = read_bytes(master_address, num_bytes_to_read).hex()
                    master_name = bytes.fromhex(master_name).decode("utf-8")
                    master_name = master_name.replace("\x0a", "\x7c")
                except UnicodeDecodeError:
                    continue
                master_name = master_name.rstrip("|")
                data = master_data
                if master_name:
                    for item in data:
                        key, value = list(data[item].items())[0]
                        if master_name == key:
                            if value:
                                master_name = value
                                master_name = master_name.replace("\x7c", "\x0a")
                                try:
                                    write_bytes(master_address, master_name.encode("utf-8") + b"\x00")
                                    logger.debug(f"Wrote quest {master_name}.")
                                except Exception as e:
                                    logger.warning("INFO ONLY: Failed to write master quest.")
    except TypeError:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.")
        sys.exit()
    except Exception as e:
        logger.error(f"Cannot find DQX process. Must have closed? Exiting.\nError: {e}")
        sys.exit()


def loop_scan_for_walkthrough():
    """
    Scans for the walkthrough address in an infinite loop and translates when found.
    """
    api_details = determine_translation_service()
    logger.info("Will watch for walkthrough text.")

    while True:
        try:
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
                                        logger.warning("INFO ONLY: Failed to write walkthrough text.")
                        else:
                            time.sleep(0.5)
            else:
                time.sleep(0.5)
        except TypeError:
            logger.error(f"Cannot find DQX process. Must have closed? Exiting.")
            sys.exit()
        except Exception as e:
            logger.error(f"Cannot find DQX process. Must have closed? Exiting.\nError: {e}")
            sys.exit()


def run_scans(player_names=True, npc_names=True, master_quest=True, communication_window=True, debug=False):
    """
    Run chosen scans.

    :param player_names: Run player name scans.
    :param npc_names: Run NPC name scans.
    :param master_quest: Run master quest scans.
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
    if master_quest:
        logger.warning("Master quest has been disabled until we find a better pattern to search for. Sorry!")
    if not communication_window:
        logger.info("Will watch for new game files.")

    while True:
        try:
            if player_names:
                scan_for_player_names()
                scan_for_menu_ai_names()
            if npc_names:
                scan_for_npc_names()
                scan_for_concierge_names()
            if master_quest:
                pass
                # scan_for_master_quests()
            if not communication_window:
                scan_for_adhoc_files()
        except TypeError:
            logger.error(f"Cannot find DQX process. Must have closed? Exiting.")
            sys.exit()
        except Exception as e:
            logger.error(f"Cannot find DQX process. Must have closed? Exiting.\nError: {e}")
            sys.exit()
