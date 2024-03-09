from common.memory import MemWriter
from common.signatures import notice_string
from loguru import logger as log

import ctypes
import subprocess
import time


def is_dqx_process_running():
    """Return True if DQX is currently running."""
    # This is difficult to do with native Python or ctypes as user locale settings
    # vary widely across the globe, so decoding the stdout cannot be relied on.
    # We will just check the exit code of a common Windows command to find this.
    # tasklist does not produce an exit code on failed lookups, but find does.
    call = 'TASKLIST /FI "imagename eq DQXGame.exe" | find "DQXGame" > nul'

    try:
        subprocess.check_call(call, shell=True)
        return True
    except subprocess.CalledProcessError:
        return False


def check_if_running_as_admin():
    """Return True if the user is running this script as an admin."""
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
