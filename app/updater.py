import zipfile
import os
import shutil
from pathlib import Path
import requests
from common.errors import message_box_fatal_error


FILES_COPIED = 0

os.system("taskkill /f /im DQXClarity.exe >nul 2>&1")
print("Clarity is updating. Please wait...")

try:
    Path("weblate.zip").unlink()
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
    zipObj.extractall("update_temp")
    # Path('update_temp/dqxclarity/clarity.ahk').unlink()
    Path("update_temp/dqxclarity/misc_files/clarity_dialog.db").unlink()
    Path("update_temp/dqxclarity/misc_files/python39.dll").unlink()
    shutil.rmtree("update_temp/dqxclarity/json", ignore_errors=True)
    Path("update_temp/dqxclarity/user_settings.ini").unlink()
    # shutil.rmtree('update_temp/dqxclarity/bms', ignore_errors=True)
    # shutil.rmtree('update_temp/dqxclarity/imgs', ignore_errors=True)


Path("dqxclarity.zip").unlink()
UPDATE_FILE_PATH = "update_temp/dqxclarity"
update_files = os.listdir(UPDATE_FILE_PATH)

for file in update_files:
    full_file_name = os.path.join(UPDATE_FILE_PATH, file)
    # print(full_file_name)

    if os.path.isdir(full_file_name):
        # if(os.path.exists(os.path.join(os.getcwd(), file))):
        # shutil.rmtree(os.path.join(os.getcwd(), file))
        # shutil.copytree(full_file_name, os.getcwd())
        sub_folder_files = os.listdir(full_file_name)
        for subfile in sub_folder_files:
            full_subfile_name = os.path.join(full_file_name, subfile)
            # print("SUB FILE:" + full_subfile_name)
            if full_subfile_name != "update_temp/dqxclarity\\pymem\\ressources":
                try:
                    shutil.copy(full_subfile_name, os.path.join(os.getcwd(), file))
                    # print("Subfile copied to " + os.path.join(os.getcwd(), file))
                    FILES_COPIED = FILES_COPIED + 1
                except shutil.SameFileError:
                    pass
    else:
        try:
            shutil.copy(full_file_name, os.getcwd())
            FILES_COPIED = FILES_COPIED + 1
            # print("File copied to " + os.getcwd())
        except shutil.SameFileError:
            pass

shutil.rmtree("update_temp", ignore_errors=True)
message_box_fatal_error("Success", "Update complete. Please press OK and relaunch Clarity.")
