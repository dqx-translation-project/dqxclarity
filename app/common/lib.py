import logging
import csv
import json
import shutil
import re
from pathlib import Path
from loguru import logger
from common.errors import message_box_fatal_error
from common.memory import read_bytes


def generate_hex(file: str):
    """Parses a nested json file to convert strings to hex."""
    en_hex_to_write = ""
    data = read_json_file(file)
    for item in data:
        key, value = list(data[item].items())[0]
        if re.search("^clarity_nt_char", key):
            en = "00"
        elif re.search("^clarity_ms_space", key):
            en = "00e38080"
        else:
            ja = key.encode("utf-8").hex() + "00"
            ja_raw = key
            ja_len = len(ja)
            if value:
                en = value.encode("utf-8").hex() + "00"
                en_raw = value
                en_len = len(en)
            else:
                en = ja
                en_len = ja_len
            if en_len > ja_len:
                logger.error("\n")
                logger.error("String too long. Please fix and try again.")
                logger.error(f"File: {file}.json")
                logger.error(f"JA string: {ja_raw} (byte length: {ja_len})")
                logger.error(f"EN string: {en_raw} (byte length: {en_len})")
                message_box_fatal_error(
                    "Byte Error",
                    "One of the translated strings is too long. Please go let the translators in the #clarity-bug-reports channel know so they can fix it.",
                )

            ja = ja.replace("7c", "0a")
            ja = ja.replace("5c74", "09")
            en = en.replace("7c", "0a")
            en = en.replace("5c74", "09")
            if ja_len != en_len:
                while True:
                    en += "00"
                    new_len = len(en)
                    if (ja_len - new_len) == 0:
                        break
        en_hex_to_write += en

    return bytes.fromhex(en_hex_to_write)


def query_csv(hex_pattern, hex_dict="misc_files/hex_dict.csv") -> dict:
    """Query CSV and return value found."""
    with open(hex_dict, encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return_dict = {}
        for row in reader:
            if row["hex_string"] == hex_pattern:
                return_dict["file"] = row["file"]
                return_dict["hex_string"] = row["hex_string"]
                return return_dict
        return None


def read_json_file(file):
    """Reads JSON file and returns content."""
    with open(file, "r", encoding="utf-8") as json_data:
        return json.loads(json_data.read())


def write_file(path, filename, attr, data):
    """Writes a string to a file."""
    with open(f"{path}/{filename}", attr, encoding="utf-8") as open_file:
        open_file.write(data)


def split_hex_into_spaces(hex_str: str):
    """
    Breaks a string up by putting spaces between every two characters.
    Used to format a hex string.
    """
    spaced_str = " ".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))
    return spaced_str.upper()


def delete_folder(folder):
    """Deletes a folder and all subfolders."""
    try:
        shutil.rmtree(folder, ignore_errors=True)
    except Exception:
        pass


def delete_file(file):
    """Deletes a file."""
    try:
        Path(file).unlink()
    except Exception:
        pass


def format_to_json(json_data, data, lang, number):
    """Accepts data that is used to return a nested json."""
    json_data[number] = {}
    if data == "":
        json_data[number][f"clarity_nt_char_{number}"] = f"clarity_nt_char_{number}"
    elif data == "　":
        json_data[number][f"clarity_ms_space_{number}"] = f"clarity_ms_space_{number}"
    else:
        if lang == "ja":
            json_data[number][data] = data
        else:
            json_data[number][data] = ""

    return json_data


def setup_logger(name, log_file, level=logging.INFO):
    """
    Sets up a logger for hook shellcode.
    """
    # pylint: disable=redefined-outer-name
    logging.basicConfig(format="%(message)s")
    formatter = logging.Formatter("%(message)s")
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    if logger.hasHandlers():
        logger.handlers.clear()

    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


def merge_jsons(files: list):
    """
    Merge any number of json files to create a new dict.

    :param files: List of files to merge
    :returns: New dict with merged changes
    """
    merged_changes = {}
    for file in files:
        json_content = read_json_file(file=file)
        for item in json_content:
            key, value = list(json_content[item].items())[0]
            merged_changes[key] = value

    return merged_changes


def dump_game_file(start_addr: int, num_bytes_to_read: int):
    """
    Dumps a game file given its start and end address. Formats into a json
    friendly file to be used by clarity for both ja and en.

    start_addr: Where to start our read operation to dump (should start at TEXT)
    num_bytes_to_read: How many bytes should we should dump from the start_addr
    """
    game_data = read_bytes(start_addr, num_bytes_to_read).hex().strip("00")
    if len(game_data) % 2 != 0:
        game_data = game_data + "0"

    game_data = bytes.fromhex(game_data).decode("utf-8")
    game_data = game_data.replace("\x0a", "\x7c")
    game_data = game_data.replace("\x00", "\x0a")
    game_data = game_data.replace("\x09", "\x5c\x74")

    jsondata_ja = {}
    jsondata_en = {}
    number = 1

    for line in game_data.split("\n"):
        json_data_ja = format_to_json(jsondata_ja, line, "ja", number)
        json_data_en = format_to_json(jsondata_en, line, "en", number)
        number += 1

    json_data_ja = json.dumps(jsondata_ja, indent=2, sort_keys=False, ensure_ascii=False)
    json_data_en = json.dumps(jsondata_en, indent=2, sort_keys=False, ensure_ascii=False)

    dic = {}
    dic["ja"] = json_data_ja
    dic["en"] = json_data_en

    return dic
