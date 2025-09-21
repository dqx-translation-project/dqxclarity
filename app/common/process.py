from common.memory import MemWriter
from common.signatures import notice_string
from loguru import logger as log
from multiprocessing import Event, Process

import ctypes
import subprocess
import time


def start_process(name: str, target, args=()):
    """Starts a new process. The target function must accept
    multiprocessing.Event as an argument. Once the process has been started,
    you must signal that the function is ready with ready_event.set() within
    the target function.

    :param name: Name of the process to start.
    :param target: The name of the function the thread will execute.
    :param args: A tuple of arguments the target will accept.
    """
    ready_event = Event()
    process_args = (ready_event,) if args is None else args + (ready_event,)

    p = Process(name=name, target=target, args=process_args)
    p.start()

    if not ready_event.wait(timeout=20.0):
        p.terminate()
        raise RuntimeError(f'Process "{name}" failed to start within the timeout.')


def is_dqx_process_running():
    """Return True if DQX is currently running."""
    # This is difficult to do with native Python or ctypes as user locale settings
    # vary widely across the globe, so decoding the stdout cannot be relied on.
    # We will just check the exit code of a common Windows command to find this.
    # tasklist does not produce an exit code on failed lookups, but find does.
    # Uses fully qualified path when calling executables as people might have
    # similarly-named tools.
    call = '%SystemRoot%\\System32\\tasklist.exe /FI "imagename eq DQXGame.exe" | %SystemRoot%\\System32\\find.exe "DQXGame" > nul'

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
    """Scans for the DQXGame.exe process.

    Returns True when found.
    """
    log.info("Launch DQX and log in to continue.")
    if is_dqx_process_running():
        log.success("DQXGame.exe found.")
        return True
    while not is_dqx_process_running():
        time.sleep(0.25)
    log.success("DQXGame.exe found. Make sure you're on the \"Important notice\" screen.")
    writer = MemWriter()
    while True:
        if writer.pattern_scan(pattern=notice_string, data_only=True):
            log.success("\"Important notice\" screen found.")
            return True
