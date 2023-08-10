import logging
import json
import os
import shutil
import pymem
from pathlib import Path


def read_json_file(file):
    """Reads JSON file and returns content."""
    with open(file, "r", encoding="utf-8") as json_data:
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


def get_abs_path(file: str):
    abs_path = os.path.abspath(os.path.join(os.path.dirname(file)))
    return abs_path.replace("\\", "/")

def scan_for_dqx():
    """
    Continually scans for DQX and
    checks if the integrity scan
    is valid.
    """
    while True:
        try:
            exe = pymem.Pymem("DQXGame.exe")
            # obscure issue seen on Windows 11 getting an OverflowError
            # https://github.com/srounet/Pymem/issues/19
            exe.process_handle &= 0xFFFFFFFF
            # try:
                # if(pattern_scan(pattern=integrity_check, module=exe)):
                    # break
            # except Exception:
                # continue
            break
        except pymem.exception.ProcessNotFound:
            continue