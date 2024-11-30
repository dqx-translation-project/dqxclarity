from common.config import UserConfig
from common.constants import (
    GITHUB_CLARITY_CUTSCENE_JSON_URL,
    GITHUB_CLARITY_DAT1_URL,
    GITHUB_CLARITY_IDX_URL,
    GITHUB_CLARITY_ITEMS_JSON_URL,
    GITHUB_CLARITY_KEY_ITEMS_JSON_URL,
    GITHUB_CLARITY_MONSTERS_JSON_URL,
    GITHUB_CLARITY_NPC_JSON_URL,
    GITHUB_CLARITY_QUESTS_REQUESTS_JSON_URL,
    GITHUB_CLARITY_VERSION_UPDATE_URL,
    GITHUB_CUSTOM_TRANSLATIONS_ZIP_URL,
)
from common.db_ops import db_query
from common.process import check_if_running_as_admin, is_dqx_process_running
from gettext import install
from io import BytesIO
from loguru import logger as log
from openpyxl import load_workbook
from subprocess import Popen
from tkinter.filedialog import askdirectory
from zipfile import ZipFile

import json
import os
import requests
import sys
import winreg


def download_custom_files() -> None:
    log.info("Downloading custom translation files from dqx-translation-project/dqx-custom-translations.")
    response = requests.get(GITHUB_CUSTOM_TRANSLATIONS_ZIP_URL, timeout=15)

    if response.status_code == 200:
        db_query("DELETE FROM m00_strings")
        zfile = ZipFile(BytesIO(response.content))
        for obj in zfile.infolist():
            if obj.filename.endswith('/'):  # directory
                continue

            if '/json/' in obj.filename and obj.filename.endswith('.json'):
                with zfile.open(obj.filename, 'r') as f:
                    data = f.read()

                # modify file path to just the name of the file without the extension
                filename = obj.filename.split('/')[-1].rsplit('.', 1)[0]
                read_custom_json_and_import(name=filename, data=data)

            if '/csv/' in obj.filename:
                if obj.filename.endswith('merge.xlsx'):
                    with zfile.open(obj.filename, 'r') as f:
                        data = f.read()

                    read_xlsx_and_import(data)

                if obj.filename.endswith('glossary.csv'):
                    with zfile.open(obj.filename, 'r') as f:
                        data = f.read()

                    read_glossary_and_import(data)

    else:
        log.exception(f"Status Code: {response.status_code}. Reason: {response.reason}")


def read_custom_json_and_import(name: str, data: str) -> None:
    content = json.loads(data)
    query_list = []

    for item in content:
        key, value = list(content[item].items())[0]

        escaped_value = value.replace("'", "''")
        query_value = f"('{key}', '{escaped_value}', '{name}')"
        query_list.append(query_value)

    insert_values = ','.join(query_list)
    query = f"INSERT INTO m00_strings (ja, en, file) VALUES {insert_values};"
    db_query(query)


def download_game_jsons() -> None:
    log.info("Downloading translation files from dqx-translation-project/dqx_translations.")

    # dqx_translations is roughly 17MB~ right now. we only need these files from that repository.
    url_to_db = {
        GITHUB_CLARITY_MONSTERS_JSON_URL: "monsters",
        GITHUB_CLARITY_NPC_JSON_URL: "npcs",
        GITHUB_CLARITY_ITEMS_JSON_URL: "items",
        GITHUB_CLARITY_KEY_ITEMS_JSON_URL: "key_items",
        GITHUB_CLARITY_QUESTS_REQUESTS_JSON_URL: "quests",
        GITHUB_CLARITY_CUTSCENE_JSON_URL: "story_names"
    }

    for url in url_to_db:
        response = requests.get(url, timeout=15)

        if response.status_code == 200:
            read_custom_json_and_import(name=url_to_db[url], data=response.content)
        else:
            log.exception(f"Status Code: {response.status_code}. Reason: {response.reason}")


def check_for_updates(update: bool) -> None:
    """Checks to see if Clarity is running the latest version of itself. If
    not, will launch updater.py and exit.

    :param update: Whether or not to update after checking for updates.
    """
    log.info("Checking dqxclarity repo for updates...")
    if not os.path.exists("version.update"):
        log.warning("Couldn't determine current version of dqxclarity. Running as is.")
        return

    with open("version.update") as file:
        cur_ver = file.read().strip()

    try:
        url = GITHUB_CLARITY_VERSION_UPDATE_URL
        github_request = requests.get(url)
    except requests.exceptions.RequestException as e:
        log.warning(f"Failed to check latest version. Running anyways.\n{e}")
        return

    try:
        release_version = github_request.json()["tag_name"]
        if release_version.startswith("v"):
            release_version = release_version[1:]
        if release_version == cur_ver:
            log.success(f"Clarity is up to date! (Current version: {str(cur_ver)})")
        else:
            log.warning(f"Clarity is out of date! (Current: {str(cur_ver)}, Latest: {str(release_version)}).")
            if update:
                install_path = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Python\PythonCore\3.11-32\InstallPath")
                python_exe = winreg.QueryValueEx(install_path, "ExecutablePath")
                if not python_exe:
                    log.warning("Did not find Python exe! Clarity is unable to update and will continue without updating.")
                    return False
                log.info(f"Launching updater.")
                Popen([python_exe[0], "./updater.py"])
                sys.exit()
        return
    except Exception as e:
        log.warning(f"There was a problem checking trying to update. Clarity will continue without updating.\n{e}")
        return


def read_xlsx_and_import(data: str) -> None:
    """We manage a file outside of this repository called merge.xlsx in dqx-
    custom-translations.

    This interacts with that file by reading entries that have been
    manually translated to fix bugs that machine translation introduced
    and inserts/updates the user's local database with override entries
    from the xlsx file.
    """
    workbook = load_workbook(BytesIO(data))
    ws_dialogue = workbook["Dialogue"]
    ws_walkthrough = workbook["Walkthrough"]
    ws_quests = workbook["Quests"]
    ws_story_so_far = workbook["Story So Far"]

    # Dialogue worksheet
    db_query("DELETE FROM fixed_dialog_template")

    values = []
    for i, _ in enumerate(ws_dialogue, start=2):
        source_text = ws_dialogue.cell(row=i, column=1).value
        en_text = ws_dialogue.cell(row=i, column=3).value
        notes = ws_dialogue.cell(row=i, column=4).value
        original_bad_string_text = ws_dialogue.cell(row=i, column=5).value

        if source_text and en_text:
            # bad_string means the machine translation that was returned ended up breaking the game or providing
            # a confusing experience. initially, what was logged in the spreadsheet was the partial string with
            # the player info taken out. we can't use that when we see the text, so we have to iterate over every
            # bad string match we have to find a match. because of how the text was collected before, this exists.
            # when we get rid of all of the partial strings and get the original source strings, we can remove this
            # logic.
            bad_string = 0
            if notes:
                if "BAD STRING" in notes:
                    if not original_bad_string_text:
                        bad_string = 1
                    else:
                        source_text = original_bad_string_text
            escaped_text = en_text.replace("'", "''")
            values.append(f"('{source_text}', '{escaped_text}', {bad_string})")

    insert_values = ",".join(values)
    query = f"INSERT OR REPLACE INTO fixed_dialog_template (ja, en, bad_string) VALUES {insert_values};"

    db_query(query)

    # Walkthrough worksheet
    values = []
    for i, _ in enumerate(ws_walkthrough, start=2):
        source_text = ws_walkthrough.cell(row=i, column=1).value
        en_text = ws_walkthrough.cell(row=i, column=3).value

        if source_text and en_text:
            escaped_text = en_text.replace("'", "''")
            values.append(f"('{source_text}', '{escaped_text}')")

    insert_values = ",".join(values)
    query = f"INSERT OR REPLACE INTO walkthrough (ja, en) VALUES {insert_values};"

    db_query(query)

    # Quests worksheet
    values = []
    for i, _ in enumerate(ws_quests, start=2):
        source_text = ws_quests.cell(row=i, column=1).value
        en_text = ws_quests.cell(row=i, column=3).value

        if source_text and en_text:
            escaped_text = en_text.replace("'", "''")
            values.append(f"('{source_text}', '{escaped_text}')")

    insert_values = ",".join(values)
    query = f"INSERT OR REPLACE INTO quests (ja, en) VALUES {insert_values};"

    db_query(query)

    # Story So Far worksheet
    values = []
    for i, _ in enumerate(ws_story_so_far, start=2):
        source_text = ws_story_so_far.cell(row=i, column=1).value
        deepl_text = ws_story_so_far.cell(row=i, column=2).value
        fixed_en_text = ws_story_so_far.cell(row=i, column=3).value

        if source_text and fixed_en_text:
            escaped_text = fixed_en_text.replace("'", "''")
            values.append(f"('{source_text}', '{escaped_text}')")
        elif source_text and deepl_text:
            escaped_text = deepl_text.replace("'", "''")
            values.append(f"('{source_text}', '{escaped_text}')")

    insert_values = ",".join(values)
    query = f"INSERT OR REPLACE INTO story_so_far_template (ja, en) VALUES {insert_values};"

    db_query(query)


def read_glossary_and_import(data: str) -> None:
    decoded_data = data.decode('utf-8')

    query_list = []
    glossary = [ x for x in decoded_data.split("\n") if x ]
    for record in glossary:
        ja, en = record.split(",", 1)

        escaped_value = en.replace("'", "''")
        query_value = f"('{ja}', '{escaped_value}')"

        query_list.append(query_value)


    drop_query = "DELETE FROM glossary;"
    db_query(drop_query)

    insert_values = ','.join(query_list)
    insert_query = f"INSERT OR REPLACE INTO glossary (ja, en) VALUES {insert_values};"
    db_query(insert_query)


def download_dat_files() -> None:
    """Downloads and applies the dat translation mod to the user's DQX
    directory."""
    if is_dqx_process_running():
        log.exception("Please close DQX before attempting to update the translated DAT/IDX file.")

    if not check_if_running_as_admin():
        log.exception(
            "dqxclarity must be running as an administrator in order to apply the dat translation mod. "
            "Please re-launch dqxclarity as an administrator and try again."
        )

    config = UserConfig()
    read_game_path = "/".join([config.game_path, "Game/Content/Data", "data00000000.win32.dat0"])

    if not os.path.exists(read_game_path):
        default_game_path = "C:/Program Files (x86)/SquareEnix/DRAGON QUEST X"

        if os.path.exists(default_game_path):
            config.update(section='config', key='installdirectory', value=default_game_path)
        else:
            log.warning(
                "Could not verify DRAGON QUEST X directory. "
                "Browse to the path where you installed the game and select the \"DRAGON QUEST X\" folder. "
                "Make sure you didn't move the data00000000.dat0 file outside of the game directory or rename it. "
                "If the file is missing, make sure you patch the game first before running this program."
            )

            while True:
                dqx_path = askdirectory()

                if not dqx_path:
                    log.error("You did not select a directory or closed the window. Program will exit.")

                dat0_path = "/".join([dqx_path, "Game/Content/Data", "data00000000.win32.dat0"])

                if os.path.isfile(dat0_path):
                    config.update(section='config', key='installdirectory', value=dqx_path)
                    log.success("DRAGON QUEST X path verified.")
                    break
                else:
                    log.warning(
                        "The path you provided is not a valid path. "
                        "Browse to the path where you installed the game and select the \"DRAGON QUEST X\" folder."
                    )

    config.reinit() # re-read config in case we changed it above.
    dqx_path = "/".join([config.game_path, "Game/Content/Data"])

    try:
        log.info("Downloading DAT1 and IDX files.")
        dat_request = requests.get(GITHUB_CLARITY_DAT1_URL, timeout=60)
        idx_request = requests.get(GITHUB_CLARITY_IDX_URL, timeout=60)

        # Make sure both requests are good before we write the files
        if (
            (dat_request.status_code == 200 and len(dat_request.content) != 0) and
            (idx_request.status_code == 200 and len(idx_request.content) != 0)
           ):
            with open(dqx_path + "/data00000000.win32.dat1", "w+b") as f:
                f.write(dat_request.content)

            with open(dqx_path + "/data00000000.win32.idx", "w+b") as f:
                f.write(idx_request.content)

            log.success("Game dat translation mod applied.")
        else:
            log.error(
                "Failed to download translation files. "
                "dqxclarity will continue without updating dat translation mod."
            )
    except Exception as e:
        log.error(f"Failed to download dat translation mod files. Error: {e}")
