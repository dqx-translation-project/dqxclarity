from locale import getencoding
from loguru import logger as log
from pathlib import Path

import json
import logging
import os
import shutil


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


def setup_logging():
    """Configures logging for dqxclarity."""
    log_path = get_project_root("logs/console.log")
    log.add(sink=log_path, level="DEBUG")

    return log


def setup_logger(name, log_file, level=logging.INFO):
    """Sets up a logger for hook shellcode."""
    # pylint: disable=redefined-outer-name
    logging.basicConfig(format="%(message)s")
    formatter = logging.Formatter("%(message)s")
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(formatter)

    log_handle = logging.getLogger(name)
    if log_handle.hasHandlers():
        log_handle.handlers.clear()

    log_handle.setLevel(level)
    log_handle.addHandler(handler)

    return log_handle


def get_project_root(add_file=None):
    """Returns the absolute path of the project root. If add_file is called,
    appends add_file to the end of the absolute path.

    :param file: File to add to absolute path.
    :returns: Absolute path to the project root or file.
    """
    abs_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
    if add_file:
        abs_path = "/".join([abs_path, add_file])
    return abs_path


def encode_to_utf8(string: str):
    """Encodes a string of the current machine's encoding to utf-8."""
    current_locale = getencoding()
    return string.encode(current_locale).decode(current_locale).encode()
