import ctypes
import ctypes.wintypes
import glob
import os
import shutil
import ssl
import sys
from io import BytesIO
from urllib.request import Request, urlopen
from zipfile import ZipFile as zip


CLARITY_URL = "https://github.com/dqx-translation-project/dqxclarity/releases/latest/download/dqxclarity.zip"


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


def is_steam_deck() -> bool:
    """Check if user is on a Steam Deck.

    :returns: Returns True if yes. Else, False.
    """
    return os.environ.get("SteamDeck") == "1"  # noqa: SIM112


def kill_exe(name: str) -> None:
    """Use taskkill to kill a running executable.

    :param name: Name of the executable to search for.
    :returns: None. Runs the taskkill command against the name.
    """
    os.system(f"taskkill /f /im {name} >nul 2>&1")


def download_latest_zip():
    # yes, this is not a great security practice, but consumers of this application
    # are not technical and troubleshooting cert issues with non-technical
    # users is both time consuming and exhausting.
    req = Request(CLARITY_URL)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data = urlopen(req, timeout=15, context=ctx)

    zfile = zip(BytesIO(data.read())) if data.status == 200 else None

    return zfile


def delete_file(file: str):
    try:
        os.remove(file)
    except OSError:
        shutil.rmtree(file, ignore_errors=True)


if is_dqx_process_running():
    input(
        "Please close DQX before updating. Re-launch dqxclarity once the game has been closed.\n\n"
        "Press ENTER to close this window."
    )
    sys.exit()

print("dqxclarity is updating. Please wait...")

# if running on steam deck, kill DQXBoot so the user can see the command prompt output easier.
if is_steam_deck():
    kill_exe("DQXBoot.exe")
    kill_exe("DQXLauncher.exe")

kill_exe("DQXClarity.exe")

try:
    z_data = download_latest_zip()
    if not z_data:
        raise
except Exception as e:
    input(
        "Failed to download the latest update. Please try again or download the update manually from Github.\n"
        "Documentation: https://dqx-translation-project.github.io/dqxclarity\n\n"
        f"Error: {e}"
    )
    sys.exit(1)

# we don't want to delete certain files/folders when updating. these
# could be old logs, existing user settings or other misc files.
ignored_files = [
    "user_settings.ini",
]

ignored_directories = [
    "misc_files",
    "logs",
]

clarity_path = os.path.split(__file__)[0]
clarity_files = glob.glob(f"{clarity_path}/**", recursive=True)

# delete all files except for ones specified in the ignored lists above.
for file in clarity_files:
    basename = os.path.basename(file)

    if any(x in file for x in ignored_directories):
        continue
    if basename in ignored_files:
        continue
    if basename:
        delete_file(file)

# unzip new files. don't overwrite any files/folders in the ignored lists above.
for obj in z_data.infolist():
    basename = os.path.basename(obj.filename)

    if any(x in obj.filename for x in ignored_directories):
        continue
    if basename in ignored_files:
        continue

    obj.filename = obj.filename.replace("dqxclarity/", "")
    if obj.filename:
        z_data.extract(obj, ".")

# remove venv so we can re-install any new modules if we introduce or bump new ones.
delete_file("venv")

input("Success. Please re-launch dqxclarity. Press ENTER to close this window.")
