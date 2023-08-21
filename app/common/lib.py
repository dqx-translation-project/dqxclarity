from locale import getencoding
from loguru import logger
from pathlib import Path

import ctypes
import json
import logging
import os
import shutil
import subprocess
import time


def read_json_file(file):
    """Reads JSON file and returns content."""
    with open(file, encoding="utf-8") as json_data:
        return json.loads(json_data.read())


def write_file(path, filename, attr, data):
    """Writes a string to a file."""
    with open(f"{path}/{filename}", attr, encoding="utf-8") as open_file:
        open_file.write(data)


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


def setup_logger(name, log_file, level=logging.INFO):
    """Sets up a logger for hook shellcode."""
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
    """Merge any number of json files to create a new dict.

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


def get_abs_path(file: str):
    abs_path = os.path.abspath(os.path.join(os.path.dirname(file)))
    return abs_path.replace("\\", "/")


def process_exists(process_name):
    # https://stackoverflow.com/a/29275361
    call = 'TASKLIST', '/FI', 'imagename eq %s' % process_name
    curr_locale = getencoding()
    output = subprocess.check_output(call).decode(curr_locale)
    last_line = output.strip().split('\r\n')[-1]
    return last_line.lower().startswith(process_name.lower())


def check_if_running_as_admin():
    """Check if the user is running this script as an admin.

    If not, return False.
    """
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    if is_admin == 1:
        return True
    return False


def wait_for_dqx_to_launch() -> bool:
    """Scans for the DQXGame.exe process."""
    logger.info("Searching for DQXGame.exe.")
    if process_exists("DQXGame.exe"):
        logger.success("DQXGame.exe found.")
        return
    while not process_exists("DQXGame.exe"):
        time.sleep(0.25)
    from common.memory import pattern_scan
    from common.signatures import notice_string
    logger.success("DQXGame.exe found. Make sure you're on the \"Important notice\" screen.")
    while True:
        if pattern_scan(pattern=notice_string):
            logger.success("\"Important notice\" screen found.")
            return
