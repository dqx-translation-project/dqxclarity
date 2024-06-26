from locale import getencoding
from loguru import logger as log

import logging
import os


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
