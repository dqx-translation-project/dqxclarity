import zipfile
import os
import shutil
from pathlib import Path
import requests
from common.errors import message_box_fatal_error


os.system("taskkill /f /im DQXClarity.exe >nul 2>&1")
print("Clarity is updating. Please wait...")

try:
    shutil.rmtree("update_temp", ignore_errors=True)
except Exception as e:
    pass

try:
    URL = "https://github.com/dqxtranslationproject/dqxclarity/releases/latest/download/dqxclarity.zip"
    r = requests.get(URL, timeout=15)
except Exception as e:
    message_box_fatal_error(
        "Timeout",
        "Timed out trying to download latest update. Please try again or download the update manually from Github.",
    )

with open("dqxclarity.zip", "wb") as weblate_zip:
    weblate_zip.write(r.content)

with zipfile.ZipFile("dqxclarity.zip", "r") as zipObj:
    Path("update_temp/dqxclarity/misc_files/clarity_dialog.db").unlink()
    Path("update_temp/dqxclarity/misc_files/python39.dll").unlink()
    Path("update_temp/dqxclarity/user_settings.ini").unlink()

Path("dqxclarity.zip").unlink()
UPDATE_FILE_PATH = "update_temp/dqxclarity"
update_files = os.listdir(UPDATE_FILE_PATH)

for file in update_files:
    full_file_name = os.path.join(UPDATE_FILE_PATH, file)
    if os.path.isdir(full_file_name):
        sub_folder_files = os.listdir(full_file_name)
        for subfile in sub_folder_files:
            full_subfile_name = os.path.join(full_file_name, subfile)
            if full_subfile_name != "update_temp/dqxclarity\\pymem\\ressources":
                try:
                    shutil.copy(full_subfile_name, os.path.join(os.getcwd(), file))
                except shutil.SameFileError:
                    pass
    else:
        try:
            shutil.copy(full_file_name, os.getcwd())
        except shutil.SameFileError:
            pass

shutil.rmtree("update_temp", ignore_errors=True)
message_box_fatal_error("Success", "Update complete. Please press OK and relaunch Clarity.")
