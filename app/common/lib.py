from loguru import logger as log

import logging
import os
import sys


def setup_logging(log_file: str = "console.log", stdout: bool = True, level: str = "INFO"):
    """Sets up logging.

    :param log_file: Name of the file to log to. Defaults to
        console.log. All logs write to the logs folder.
    :param stdout: Send logs to stdout. Useful to disable when running
        inside hooks as we can't see these anyways.
    :param level: Logging level (DEBUG, INFO, WARNING, ERROR). Defaults
        to INFO.
    :returns: A loguru logging object.
    """
    log_path = get_project_root(f"logs/{log_file}")

    try:
        log.remove(0)
    except ValueError:
        pass

    # wine does not seem to have support for ansi color codes in cmd, which
    # makes it very difficult to read the command prompt.
    colorize = True
    if is_wine_environment():
        colorize = False

    if stdout:
        log.add(sink=sys.stdout, level=level, colorize=colorize)

    # Don't colorize logs ever.
    log.add(sink=log_path, level=level, colorize=False)

    return log


def setup_logger(name: str, log_file: str, level=logging.INFO):
    """Sets up a logger for hook shellcode. This is used for custom logging
    outside of our regular logging to record strings to a file.

    :param name: Name of the logger to create.
    :param log_file: Path to the log file.
    :param level: Logging level. Defaults to INFO.
    :returns: A logging handle.
    """
    # pylint: disable=redefined-outer-name
    formatter = logging.Formatter("%(message)s")
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(formatter)

    log_handle = logging.getLogger(name)
    if log_handle.hasHandlers():
        log_handle.handlers.clear()

    log_handle.setLevel(level)
    log_handle.addHandler(handler)
    log_handle.propagate = False  # Prevent propagation to root logger

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


def is_wine_environment() -> bool:
    """Check if user is running in WINE.

    :returns: Returns True if yes. Else, False.
    """
    if os.environ.get("SteamDeck") == "1" or os.environ.get("WINEPREFIX"):
        return True
    return False
