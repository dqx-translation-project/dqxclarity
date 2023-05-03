from io import BytesIO
import glob
from zipfile import ZipFile as zip
import os
import shutil
import sys
import subprocess
from urllib.request import urlopen, Request

CLARITY_URL = "https://github.com/dqx-translation-project/dqxclarity/releases/latest/download/dqxclarity.zip"


def process_exists(process_name):
    # https://stackoverflow.com/a/29275361
    call = 'TASKLIST', '/FI', 'imagename eq %s' % process_name
    output = subprocess.check_output(call).decode()
    last_line = output.strip().split('\r\n')[-1]
    return last_line.lower().startswith(process_name.lower())


def kill_clarity_exe():
    os.system("taskkill /f /im DQXClarity.exe >nul 2>&1")


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


if process_exists("DQXGame.exe"):
    input("Please close DQX before updating. Re-launch dqxclarity once the game has been closed.\n\nPress ENTER to close this window.")
    sys.exit()

print("dqxclarity is updating. Please wait...")
kill_clarity_exe()

try:
    z_data = download_latest_zip()
    if not z_data:
        raise
except Exception as e:
    input(f"Failed to download the latest update. Please try again or download the update manually from Github.\n\nError: {e}")
    sys.exit()

# don't remove user's preferences
files_to_ignore = [
    "clarity_dialog.db",
    "user_settings.ini",
    "defaults.pref",
    "misc_files"
]

clarity_path = os.path.split(__file__)[0]
clarity_files = glob.glob(f"{clarity_path}/**", recursive=True)
for file in clarity_files:
    basename = os.path.basename(file)
    if basename in files_to_ignore:
        continue
    if basename.endswith(".json"):
        if "misc_files" in file:
            continue
    if basename:
        delete_file(file)

for obj in z_data.infolist():
    basename = os.path.basename(obj.filename)
    if basename in files_to_ignore:
        continue
    obj.filename = obj.filename.replace("dqxclarity/", "")
    if obj.filename:
        z_data.extract(obj, ".")

# remove venv so we can re-install any new modules if we introduce or bump new ones.
delete_file("venv")

input("Success. Please re-launch dqxclarity. Press ENTER to close this window.")
