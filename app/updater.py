from io import BytesIO
from urllib.request import Request, urlopen
from zipfile import ZipFile as zip

import glob
import os
import shutil
import subprocess
import sys

CLARITY_URL = "https://github.com/dqx-translation-project/dqxclarity/releases/latest/download/dqxclarity.zip"


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


def is_steam_deck() -> bool:
    """Check if user is on a Steam Deck.

    :returns: Returns True if yes. Else, False.
    """
    if os.environ.get("SteamDeck") == "1":
        return True
    return False


def kill_exe(name: str) -> None:
    """Use taskkill to kill a running executable.

    :param name: Name of the executable to search for.
    :returns: None. Runs the taskkill command against the name.
    """
    os.system(f"taskkill /f /im {name} >nul 2>&1")


def download_latest_zip():
    req = Request(CLARITY_URL)
    data = urlopen(req, timeout=15)
    if data.status == 200:
        zfile = zip(BytesIO(data.read()))
    else:
        zfile = None
    return zfile


def delete_file(file: str):
    try:
        os.remove(file)
    except:
        shutil.rmtree(file, ignore_errors=True)


if is_dqx_process_running():
    input("Please close DQX before updating. Re-launch dqxclarity once the game has been closed.\n\nPress ENTER to close this window.")
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
