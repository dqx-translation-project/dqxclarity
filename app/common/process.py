from common.memory import MemWriter
from common.signatures import notice_string
from loguru import logger as log

import ctypes
import subprocess
import time


def is_dqx_process_running():
    """Returns True if DQX is currently running."""
    # https://stackoverflow.com/a/29275361
    # will only work on windows.
    call = 'TASKLIST', '/FI', 'imagename eq DQXGame.exe'
    output = subprocess.run(call, capture_output=True, text=True).stdout
    if "DQXGame.exe" in output:
        return True

    return False


def check_if_running_as_admin():
    """Check if the user is running this script as an admin.

    If not, return False.
    """
    # will only work on windows.
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    if is_admin == 1:
        return True
    return False


def wait_for_dqx_to_launch() -> bool:
    """Scans for the DQXGame.exe process."""
    log.info("Launch DQX and log in to continue.")
    if is_dqx_process_running():
        log.success("DQXGame.exe found.")
        return
    while not is_dqx_process_running():
        time.sleep(0.25)
    log.success("DQXGame.exe found. Make sure you're on the \"Important notice\" screen.")
    writer = MemWriter()
    while True:
        if writer.pattern_scan(pattern=notice_string):
            log.success("\"Important notice\" screen found.")
            return
