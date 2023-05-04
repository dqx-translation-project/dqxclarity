from io import BytesIO
from openpyxl import load_workbook
import requests
from common.errors import message_box_fatal_error
from common.constants import (
    GITHUB_CUSTOM_TRANSLATIONS_ZIP_URL,
    GITHUB_CLARITY_VERSION_UPDATE_URL,
    GITHUB_CLARITY_MERGE_XLSX_URL,
    GITHUB_WEBLATE_ZIP_URL,
)
from loguru import logger
import os
import sqlite3
from zipfile import ZipFile as zip


def download_custom_files():
    try:
        logger.info("Downloading custom json files.")
        url = GITHUB_CUSTOM_TRANSLATIONS_ZIP_URL
        request = requests.get(url, timeout=15)
        if request.status_code == 200:
            zfile = zip(BytesIO(request.content))
            for obj in zfile.infolist():
                if obj.filename[-1] == "/":  # don't parse directories
                    continue
                obj.filename = os.path.basename(
                    obj.filename
                )  # unzipped files copy zip folder structure, so re-assign filename to basename when we extract
                if obj.filename == "glossary.csv" or "custom_" in obj.filename:
                    zfile.extract(obj, "json/_lang/en")
                if obj.filename in ["hex_dict.csv", "merge.xlsx"]:
                    zfile.extract(obj, "misc_files")
        else:
            logger.error(f"Failed to download custom files. Did not get 200 from github.com.")
            message_box_fatal_error(
                "Error",
                "Failed to download custom files.\nRelaunch Clarity without 'Grab Latest Translations' and try again.",
            )
    except Exception as e:
        logger.error(f"Failed to download custom files. Error: {e}")
        message_box_fatal_error(
            "Error",
            "Failed to download custom files. See the Powershell window for details.\nRelaunch Clarity without 'Grab Latest Translations' and try again.",
        )


def check_for_updates():
    """Checks github for updates."""
    logger.info("Checking DQXclarity repo for updates...")
    if not os.path.exists("version.update"):
        logger.warning("Couldn't determine current version of dqxclarity. Running as is.")
        return

    with open("version.update", "r") as file:
        cur_ver = file.read().strip()

    try:
        url = GITHUB_CLARITY_VERSION_UPDATE_URL
        github_request = requests.get(url)
    except requests.exceptions.RequestException as e:
        logger.warning(f"Failed to check latest version. Running anyways. Message: {e}")
        return

    if github_request.text != cur_ver:
        logger.warning(f"Clarity is out of date (Current: {str(cur_ver)}, Latest: {str(github_request.text)}).")
    else:
        logger.info(f"Clarity is up to date! (Current version: {str(cur_ver)})")

    return


def get_latest_and_merge_db():

    file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "misc_files/merge.xlsx"))
    records_inserted = 0
    records_updated = 0

    if os.path.exists(file):
        os.remove(file)

    try:
        url = GITHUB_CLARITY_MERGE_XLSX_URL
        r = requests.get(url, timeout=15)
    except Exception as e:
        message_box_fatal_error("Timeout", str(e))

    file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "misc_files/merge.xlsx"))
    with open(file, "wb") as merge:
        merge.write(r.content)
        logger.info("Local database file downloaded.")

    if os.path.exists(file):
        wb = load_workbook(file)
        ws_dialogue = wb["Dialogue"]
        ws_walkthrough = wb["Walkthrough"]

        ###Dialogue insertion
        for rowNum in range(2, ws_dialogue.max_row + 1):
            source_text = ws_dialogue.cell(row=rowNum, column=1).value
            en_text = ws_dialogue.cell(row=rowNum, column=3).value

            escaped_text = en_text.replace("'", "''")
            table = "dialog"
            npc_name = ""
            language = "en"
            # bad_string = "魔物の軍団は　撤退していった。"
            bad_string = False
            bad_string_col = str(ws_dialogue.cell(row=rowNum, column=4).value)
            if "BAD STRING" in bad_string_col:
                bad_string = True

            try:
                db_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "misc_files/clarity_dialog.db"))
                conn = sqlite3.connect(db_file)
                if bad_string:
                    selectQuery = f"SELECT ja FROM dialog WHERE ja LIKE '%{source_text}%'"
                else:
                    selectQuery = f"SELECT ja FROM dialog WHERE ja = '{source_text}'"
                if bad_string:
                    updateQuery = f"UPDATE dialog SET en = '{escaped_text}' WHERE ja LIKE '%{source_text}%'"
                else:
                    updateQuery = f"UPDATE dialog SET en = '{escaped_text}' WHERE ja = '{source_text}'"
                if not bad_string:
                    insertQuery = f"INSERT INTO dialog (ja, npc_name, en) VALUES ('{source_text}', '{npc_name}', '{escaped_text}')"
                else:
                    insertQuery = ""

                cursor = conn.cursor()
                results = cursor.execute(selectQuery)

                if results.fetchone() is None and insertQuery != "":
                    cursor.execute(insertQuery)
                    records_inserted = records_inserted + 1
                else:
                    cursor.execute(updateQuery)
                    records_updated = records_updated + 1

                conn.commit()
                cursor.close()
            except sqlite3.Error as e:
                raise Exception(f"Unable to write data to table: {e}")
            finally:
                if conn:
                    conn.close()

        ###Walkthrough insertion
        for rowNum in range(2, ws_walkthrough.max_row + 1):
            source_text = ws_walkthrough.cell(row=rowNum, column=1).value
            en_text = ws_walkthrough.cell(row=rowNum, column=3).value

            escaped_text = en_text.replace("'", "''")

            try:
                db_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "misc_files/clarity_dialog.db"))
                conn = sqlite3.connect(db_file)
                selectQuery = f"SELECT ja FROM walkthrough WHERE ja = '{source_text}'"

                updateQuery = f"UPDATE walkthrough SET en = '{escaped_text}' WHERE ja = '{source_text}'"
                insertQuery = f"INSERT INTO walkthrough (ja, en) VALUES ('{source_text}', '{escaped_text}')"

                cursor = conn.cursor()
                results = cursor.execute(selectQuery)

                if results.fetchone() is None:
                    cursor.execute(insertQuery)
                    records_inserted = records_inserted + 1
                else:
                    cursor.execute(updateQuery)
                    records_updated = records_updated + 1

                conn.commit()
                cursor.close()
            except sqlite3.Error as e:
                raise Exception(f"Unable to write data to table: {e}")
            finally:
                if conn:
                    conn.close()

        logger.info(str(records_inserted) + " records were inserted into local db.")
        logger.info(str(records_updated) + " records in local db were updated.")


def get_latest_from_weblate():
    """
    Downloads the latest zip file from the weblate branch and
    extracts the json files into the appropriate folder.
    """
    logger.info("Downloading from weblate has been disabled. (Don't worry, this is intentional.)")
    # try:
        # url = GITHUB_WEBLATE_ZIP_URL
        # request = requests.get(url, timeout=15)
        # if request.status_code == 200:
            # zfile = zip(BytesIO(request.content))
            # for obj in zfile.infolist():
                # if obj.filename[-1] == "/":  # don't parse directories
                    # continue
                # if "json/_lang/en/" in obj.filename:
                    # obj.filename = os.path.basename(
                        # obj.filename
                    # )  # unzipped files copy zip folder structure, so re-assign filename to basename when we extract
                    # zfile.extract(obj, "json/_lang/en")
        # else:
            # logger.error(f"Failed to download translation files. Did not get 200 from github.com.")
            # message_box_fatal_error(
                # "Error",
                # "Failed to download custom files.\nRelaunch Clarity without 'Grab Latest Translations' and try again.",
            # )

    # except Exception as e:
        # logger.error(f"Failed to download custom files. Error: {e}")
        # message_box_fatal_error(
            # "Error",
            # "Failed to download custom files. See the Powershell window for details.\nRelaunch Clarity without 'Grab Latest Translations' and try again.",
        # )
    download_custom_files()
    get_latest_and_merge_db()
    logger.info("Now up to date!")
