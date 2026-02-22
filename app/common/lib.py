import contextlib
import os
import sys
from loguru import logger as log


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

    with contextlib.suppress(ValueError):
        log.remove(0)

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
    return os.environ.get("SteamDeck") == "1" or os.environ.get("WINEPREFIX")  # noqa: SIM112
