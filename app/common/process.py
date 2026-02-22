import ctypes
import ctypes.wintypes
import time
from loguru import logger as log


def is_dqx_process_running():
    """Return True if DQX is currently running.

    Uses the Windows API directly with Unicode functions (Process32FirstW,
    Process32NextW) to avoid locale/code page issues that occur when decoding
    process names from subprocess output.
    """

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.wintypes.DWORD),
            ("cntUsage", ctypes.wintypes.DWORD),
            ("th32ProcessID", ctypes.wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.wintypes.DWORD),
            ("cntThreads", ctypes.wintypes.DWORD),
            ("th32ParentProcessID", ctypes.wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),  # MAX_PATH, Unicode
        ]

    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    kernel32 = ctypes.windll.kernel32

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return False

    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return False

        while True:
            if entry.szExeFile.lower() == "dqxgame.exe":
                return True
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break

        return False
    finally:
        kernel32.CloseHandle(snapshot)


def check_if_running_as_admin():
    """Return True if the user is running this script as an admin."""
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()

    return is_admin == 1


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
    log.success("DQXGame.exe found.")
    return True
