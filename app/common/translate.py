import textwrap
import requests
import json
import configparser
import shutil
import unicodedata
from common.errors import warning_message, message_box_fatal_error
from common.lib import merge_jsons
import os
import langdetect
import re
import pykakasi
import sqlite3
from openpyxl import load_workbook
import deepl
import hashlib
from loguru import logger


def deepl_translate(dialog_text, api_key, region_code):
    """
    Use DeepL Translate to translate text to the specified language.
    """
    user_config = load_user_config()
    glossary_id = user_config["glossary"]["glossaryid"]
    if user_config["translation"]["regioncode"].lower() == "en":
        region_code = "en-us"
    translator = deepl.Translator(api_key)

    if glossary_id:
        response = translator.translate_text(
            text=dialog_text, source_lang="ja", target_lang=region_code, glossary=glossary_id
        )
    else:
        response = translator.translate_text(text=dialog_text, source_lang="ja", target_lang=region_code)

    return response.text


def google_translate(dialog_text, api_key, region_code):
    """Uses Google Translate to translate text to the specified language."""
    uri = "&source=ja&target=" + region_code + "&q=" + dialog_text + "&format=text"
    api_url = "https://www.googleapis.com/language/translate/v2?key=" + api_key + uri
    headers = {"Content-Type": "application/json"}
    r = requests.post(api_url, headers=headers, timeout=5)
    request_return = r.content
    if r.status_code == 200:
        return json.loads(request_return)["data"]["translations"][0]["translatedText"]
    elif r.status_code == 400:
        raise Exception("Your Google Translate API key is not valid. Check the key and try again.")
    elif r.status_code == 408:
        raise Exception(
            "Google Translate timed out making a translation request. This is not a Clarity issue. Google Translate could be having issues. Try again later."
        )
    else:
        error = json.loads(request_return)["error"]["message"]
        raise Exception(f"Google Translate returned an error: {error}")


def translate(translation_service, dialog_text, api_key, region_code):
    if translation_service == "deepl":
        return deepl_translate(dialog_text, api_key, region_code)
    elif translation_service == "google":
        return google_translate(dialog_text, api_key, region_code)


def glossary_checksum(glossary_path="json/_lang/en/glossary.csv") -> str:
    """
    Returns an md5 hash of the glossary_path file.

    :param glossary_path: Path to the glossary.csv file.
    :returns: md5 hash of the glossary.csv file.
    """
    cur_hash = ""
    if os.path.exists(glossary_path):
        with open(glossary_path, "rb") as f:
            bytes = f.read()
            cur_hash = hashlib.md5(bytes).hexdigest()
    else:
        try:
            url = "https://raw.githubusercontent.com/dqxtranslationproject/dqxclarity/weblate/json/_lang/en/glossary.csv"
            r = requests.get(url, timeout=15)
        except Exception as e:
            logger.warning("Error checking Github for glossary: {e}")
            message_box_fatal_error(
                "Timeout", "Timed out trying to reach github.com. Relaunch DQXClarity and try again."
            )

        with open(glossary_path, "wb") as glossary_csv:
            glossary_csv.write(r.content)

    return cur_hash


def refresh_glossary_id(glossary_csv_file="json/_lang/en/glossary.csv"):
    """
    Deletes and creates a new glossary ID for the DeepL Translate service.

    :param glossary_csv_file: Relative path to the glossary.csv file.
    """
    user_config = load_user_config()
    api_key = user_config["translation"]["deepltranslatekey"]
    curr_glossary_id = user_config["glossary"]["glossaryid"]
    curr_glossary_checksum = user_config["glossary"]["glossarychecksum"]
    enabledeepltranslate = user_config["translation"]["enabledeepltranslate"]
    translator = deepl.Translator(api_key)

    if enabledeepltranslate == "True" and api_key != "":
        update_glossary = False
        md5 = glossary_checksum()
        if curr_glossary_id:
            if md5 != curr_glossary_checksum:
                update_glossary = True
            try:
                # If there is a glossary in the user's config, but DeepL doesn't know about it,
                # we'll update it.
                translator.get_glossary(glossary_id=curr_glossary_id)
            except deepl.exceptions.GlossaryNotFoundException:
                update_glossary = True
        else:
            update_glossary = True

        if update_glossary:
            glossaries = translator.list_glossaries()
            for glossary in glossaries:
                if curr_glossary_id == glossary.glossary_id:
                    translator.delete_glossary(glossary=glossary.glossary_id)

            try:
                with open(glossary_csv_file, "r", encoding="utf-8-sig") as g_csv:
                    contents = g_csv.read()

                glossary_dict = {}
                for entry in contents.split("\n"):
                    line = entry.split(",", 1)
                    if line[0]:
                        glossary_dict.update({line[0]: line[1]})

                glossary = translator.create_glossary(
                    name="DQX Glossary", source_lang="ja", target_lang="en", entries=glossary_dict
                )
                update_user_config(section="glossary", key="glossaryid", value=glossary.glossary_id)
                update_user_config(section="glossary", key="glossarychecksum", value=md5)
                logger.info("Glossary updated!")
            except Exception as e:
                update_user_config(section="glossary", key="glossaryid", value="")
                update_user_config(section="glossary", key="glossarychecksum", value="")
                logger.warning(f"Glossary error: {e}")
                warning_message(
                    title="[dqxclarity] Glossary error",
                    message="There was a problem creating the glossary. The glossary feature will be disabled for this session.",
                )


def sanitized_dialog_translate(
    translation_service, dialog_text, api_key, region_code, text_width=45, max_lines=None
) -> str:
    """
    Does a bunch of text sanitization to handle tags seen in DQX, as well as automatically
    splitting the text up into chunks to be fed into the in-game dialog window.
    """
    bad_dialogue = False
    fixed_string = deal_with_icky_strings(dialog_text)

    # icky_string = "魔物の軍団は　撤退していった。"
    if fixed_string:
        bad_dialogue = True

    if detect_lang(dialog_text):
        if not bad_dialogue:
            output = re.sub("<br>", " ", dialog_text)
            output = re.split(r"(<.+?>)", output)
            final_string = ""
            for item in output:
                if item == "":
                    continue
                if item == "<br>":  # we'll manage our own line breaks later
                    final_string += " "
                    continue
                alignment = [
                    "<center>",
                    "<right>",
                ]  # center and right aligned text doesn't work well in this game with ascii
                if item in alignment:
                    final_string += ""
                    continue
                if re.findall("<(.*?)>", item, re.DOTALL) or item == "\n":
                    final_string += item
                else:
                    # lists don't have puncuation. remove new lines before sending to translate
                    puncs = ["。", "？", "！"]
                    if any(x in item for x in puncs):
                        sanitized = re.sub("\n", " ", item) + "\n"
                        sanitized = re.sub("\u3000", " ", sanitized)  # replace full width spaces with ascii spaces
                        sanitized = re.sub(
                            "「", "", sanitized
                        )  # these create a single double quote, which look weird in english
                        sanitized = re.sub("…", "", sanitized)  # elipsis doesn't look natural
                        sanitized = re.sub(
                            "", "", sanitized
                        )  # romaji player names use this. remove as it messes up the translation
                        translation = translate(translation_service, sanitized, api_key, region_code)
                        translation = translation.strip()
                        translation = re.sub(
                            "   ", " ", translation
                        )  # translation sometimes comes back with a strange number of spaces
                        translation = re.sub("  ", " ", translation)
                        translation = textwrap.fill(
                            translation, width=text_width, replace_whitespace=False, max_lines=max_lines
                        )

                        # figure out where to put <br> to break up text
                        count = 1
                        count_list = [3, 6, 9, 12, 15, 18, 21, 24, 27, 30]
                        for line in translation.split("\n"):
                            final_string += line
                            if count in count_list:
                                final_string += "\n<br>\n"
                            else:
                                final_string += "\n"
                            count += 1

                    else:
                        sanitized = item
                        sanitized = re.sub("\u3000", " ", sanitized)  # replace full width spaces with ascii spaces
                        sanitized = re.sub(
                            "「", "", sanitized
                        )  # these create a single double quote, which look weird in english
                        sanitized = re.sub("…", "", sanitized)  # elipsis doesn't look natural with english
                        translation = translate(translation_service, sanitized, api_key, region_code)
                        final_string += translation

                    def rreplace(s, old, new, occurrence):
                        li = s.rsplit(old, occurrence)
                        return new.join(li)

                    # this cleans up any blank newlines
                    final_string = "\n".join([ll.rstrip() for ll in final_string.splitlines() if ll.strip()])

                    # the above code adds a line break every 3 lines, but doesn't account for the last section
                    # of dialog that doesn't need a <br> if it's just one window of dialog, so remove it
                    final_string_count = final_string.count("\n")
                    count = 0
                    for line in final_string.split("\n"):
                        if count == final_string_count:
                            if "<br>" in line:
                                final_string = rreplace(final_string, "<br>", "", 1)
                                final_string = "\n".join(
                                    [ll.rstrip() for ll in final_string.splitlines() if ll.strip()]
                                )
                        count += 1

                    # remove accented characters as the game can't handle them
                    # unfortunately, this might make reading the game in other languages confusing or inaccurate,
                    # but the game only displays japanese and ascii.
                    final_string = unicodedata.normalize("NFKD", final_string).encode("ascii", "ignore").decode()
            return final_string
        else:
            return fixed_string
    else:
        return dialog_text


def quest_translate(translation_service, quest_text, api_key, region):
    """
    Translates quest text and fits it into the quest window.
    """
    db_quest_text = sqlite_read(quest_text, region, "quests")
    if db_quest_text:
        return db_quest_text

    full_text = re.sub("\n", " ", quest_text)
    translation = translate(translation_service, full_text, api_key, region)
    if translation:
        formatted_translation = textwrap.fill(translation, width=45, replace_whitespace=False)
        sqlite_write(quest_text, "quests", formatted_translation, region)

    return formatted_translation


def sqlite_read(text_to_query, language, table):
    """Reads text from a SQLite table."""
    escaped_text = text_to_query.replace("'", "''")

    try:
        db_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "misc_files/clarity_dialog.db"))
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        selectQuery = f"SELECT {language} FROM {table} WHERE ja = '{escaped_text}'"
        cursor.execute(selectQuery)
        results = cursor.fetchone()

        if results is not None:
            return results[0].replace("''", "'")
        else:
            return None

    except sqlite3.Error as e:
        raise Exception(f"Failed to query {table}: {e}")
    finally:
        if conn:
            conn.close()


def sqlite_write(source_text, table, translated_text, language, npc_name=""):
    """Writes or updates text to the SQLite database."""
    escaped_text = translated_text.replace("'", "''")

    try:
        db_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "misc_files/clarity_dialog.db"))
        conn = sqlite3.connect(db_file)
        selectQuery = f"SELECT ja FROM {table} WHERE ja = '{source_text}'"
        updateQuery = f"UPDATE {table} SET {language} = '{escaped_text}' WHERE ja = '{source_text}'"
        if table == "dialog":
            insertQuery = f"INSERT INTO {table} (ja, npc_name, {language}) VALUES ('{source_text}', '{npc_name}', '{escaped_text}')"
        elif table == "quests" or table == "walkthrough":
            insertQuery = f"INSERT INTO {table} (ja, {language}) VALUES ('{source_text}', '{escaped_text}')"
        else:
            raise Exception("Unknown table.")

        cursor = conn.cursor()
        results = cursor.execute(selectQuery)

        if results.fetchone() is None:
            cursor.execute(insertQuery)
        else:
            cursor.execute(updateQuery)

        conn.commit()
        cursor.close()
    except sqlite3.Error as e:
        raise Exception(f"Unable to write data to table: {e}")
    finally:
        if conn:
            conn.close()


def load_user_config(filename="user_settings.ini"):
    """
    Returns a user's config settings.
    If the config doesn't exist, a default config is generated.
    If the user's config is missing values, we back up the old
    config and generate a new default one for them.

    :param filename: Filename of the user_settings.ini file.
    :returns: Dict of config.
    """
    base_config = configparser.ConfigParser()
    base_config["translation"] = {
        "enabledeepltranslate": False,
        "deepltranslatekey": "",
        "enablegoogletranslate": False,
        "googletranslatekey": "",
        "regioncode": "en",
    }
    base_config["behavior"] = {"enabledialoglogging": "False"}
    base_config["glossary"] = {"glossaryid": "", "glossarychecksum": ""}

    def create_base_config():
        with open(filename, "w+") as configfile:
            base_config.write(configfile)

    # Create the config if it doesn't exist
    if not os.path.exists(filename):
        create_base_config()

    # Verify the integrity of the config. If a key is missing,
    # trigger user_config_state and create a new one, backing
    # up the old config.
    user_config = configparser.ConfigParser()
    user_config_state = 0
    user_config.read(filename)
    for section in base_config.sections():
        if section not in user_config.sections():
            user_config_state = 1
            break
        for key, val in base_config.items(section):
            if key not in user_config[section]:
                user_config_state = 1
                break

    # Notify user their config is busted
    if user_config_state == 1:
        shutil.copyfile(filename, f"{filename}.invalid")
        create_base_config()
        warning_message(
            title="[dqxclarity] New config created",
            message=f"We found a missing config value in your {filename}.\n\nYour old config has been renamed to {filename}.invalid in case you need to reference it.\n\nPlease relaunch dqxclarity after setting up your new configuration.",
            exit_prog=True,
        )

    config_dict = {}
    good_config = configparser.ConfigParser()
    good_config.read(filename)
    for section in good_config.sections():
        config_dict[section] = {}
        for key, val in good_config.items(section):
            config_dict[section][key] = val

    return config_dict


def update_user_config(section: str, key: str, value: str, filename="user_settings.ini"):
    """
    Updates an existing configuration option in a user's config.

    :param section: Section of the config
    :param key: Key in the section's config
    :param value: Value of the key
    :param filename: Filename of the user's config settings.
    """
    config = configparser.ConfigParser()
    config.read(filename)
    config.set(section, key, value)
    with open(filename, "w+") as configfile:
        config.write(configfile)


def determine_translation_service():
    """
    Parses the user_settings file to get information needed
    to make translation calls.
    """
    config = load_user_config()
    enabledeepltranslate = config["translation"]["enabledeepltranslate"]
    deepltranslatekey = config["translation"]["deepltranslatekey"]
    enablegoogletranslate = config["translation"]["enablegoogletranslate"]
    googletranslatekey = config["translation"]["googletranslatekey"]
    regioncode = config["translation"]["regioncode"]
    enabledialoglogging = config["behavior"]["enabledialoglogging"]

    reiterate = "Either open the user_settings.ini file in Notepad or use the API settings button in the DQXClarity launcher to set it up."

    if enabledeepltranslate == "False" and enablegoogletranslate == "False":
        warning_message(
            title="[dqxclarity] No translation service enabled",
            message=f"You need to enable a translation service. {reiterate}\n\nCurrent values:\n\nenabledeepltranslate: {enabledeepltranslate}\nenablegoogletranslate: {enablegoogletranslate}",
            exit_prog=True,
        )

    if enabledeepltranslate == "True" and enablegoogletranslate == "True":
        warning_message(
            title="[dqxclarity] Too many translation serviced enabled",
            message=f"Only enable one translation service. {reiterate}\n\nCurrent values:\n\nenabledeepltranslate: {enabledeepltranslate}\nenablegoogletranslate: {enablegoogletranslate}",
            exit_prog=True,
        )

    if enabledeepltranslate != "True" and enabledeepltranslate != "False":
        warning_message(
            title="[dqxclarity] Misconfigured boolean",
            message=f"Invalid value detected for enabledeepltranslate. {reiterate}\n\nValid values are: True, False\n\nCurrent values:\n\nenabledeepltranslate: {enabledeepltranslate}",
            exit_prog=True,
        )

    if enablegoogletranslate != "True" and enablegoogletranslate != "False":
        warning_message(
            title="[dqxclarity] Misconfigured boolean",
            message=f"Invalid value detected for enablegoogletranslate. {reiterate}\n\nValid values are: True, False\n\nCurrent values:\n\nenablegoogletranslate: {enablegoogletranslate}",
            exit_prog=True,
        )

    if deepltranslatekey == "" and googletranslatekey == "":
        warning_message(
            title="[dqxclarity] No API key configured",
            message=f"You need to configure an API key. {reiterate}",
            exit_prog=True,
        )

    if enabledialoglogging != "True" and enabledialoglogging != "False":
        warning_message(
            title="[dqxclarity] Misconfigured boolean",
            message=f"Invalid value detected for enabledialoglogging. {reiterate}\n\nValid values are: True, False\n\nCurrent values:\n\enabledialoglogging: {enabledialoglogging}",
            exit_prog=True,
        )

    if enabledeepltranslate == "True" and deepltranslatekey == "":
        warning_message(
            title="[dqxclarity] No DeepL key specified",
            message=f"DeepL is enabled, but no key was provided. {reiterate}",
            exit_prog=True,
        )

    if enablegoogletranslate == "True" and googletranslatekey == "":
        warning_message(
            title="[dqxclarity] No Google API key specified",
            message=f"Google API is enabled, but no key was provided. {reiterate}",
            exit_prog=True,
        )

    dic = {}
    if enabledeepltranslate == "True":
        dic["TranslateService"] = "deepl"
        dic["TranslateKey"] = deepltranslatekey
    elif enablegoogletranslate == "True":
        dic["TranslateService"] = "google"
        dic["TranslateKey"] = googletranslatekey

    dic["RegionCode"] = regioncode
    dic["EnableDialogLogging"] = enabledialoglogging

    return dic


def query_string_from_file(text: str, file: str) -> str:
    """
    Searches for a string from the specified json file and either returns
    the string or returns False if no match found.

    text: The text to search
    file: The name of the file (leave off the file extension)
    """
    data = read_json_file("json/_lang/en/" + file + ".json")

    for item in data:
        key, value = list(data[item].items())[0]
        if re.search(f"^{text}+$", key):
            if value:
                return value


def clean_up_and_return_items(text: str) -> str:
    """
    Cleans up unnecessary text from item strings and searches for the name in items.json.
    Used specifically for the quest window.
    """
    quest_rewards = merge_jsons(["json/_lang/en/key_items.json", "json/_lang/en/items.json", "json/_lang/en/custom_quest_rewards.json"])
    line_count = text.count("\n")
    sanitized = re.sub("男は ", "", text)  # remove boy reference from start of string
    sanitized = re.sub("女は ", "", sanitized)  # remove girl reference from start of string
    sanitized = re.sub("！　と頼まれた。", "と頼まれた。", sanitized)  # remove annoying 'asked to' string
    final_string = ""
    for item in sanitized.split("\n"):
        original = item
        quantity = ""
        no_bullet = re.sub("(^\・)", "", item)
        points = no_bullet[6:18]
        if no_bullet.endswith("こ"):
            quantity = "(" + unicodedata.normalize("NFKC", no_bullet[-2]) + ")"
            no_bullet = re.sub("(　　.*)", "", no_bullet)
        if no_bullet in quest_rewards:
            value = quest_rewards.get(no_bullet)
            if value:
                if "・" in original:
                    if line_count == 0:
                        return "・" + value + quantity
                    else:
                        final_string += "・" + value + quantity + "\n"
                else:
                    if line_count == 0:
                        return value + quantity
                    else:
                        final_string += value + quantity + "\n"
        else:
            if line_count == 0:
                if "討伐ポイント" in original:
                    return "・" + "Experience Points" + points
                else:
                    return text
            else:
                final_string += item + "\n"
    return final_string.rstrip()


def deal_with_icky_strings(text) -> str:
    fixed_string = ""
    file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "misc_files/merge.xlsx"))
    if os.path.exists(file):
        wb = load_workbook(file)
        ws_dialogue = wb["Dialogue"]
        for rowNum in range(2, ws_dialogue.max_row + 1):
            jp_string = str(ws_dialogue.cell(row=rowNum, column=1).value)
            bad_string_col = str(ws_dialogue.cell(row=rowNum, column=4).value)
            if (jp_string in text) and ("BAD STRING" in bad_string_col):
                fixed_string = str(ws_dialogue.cell(row=rowNum, column=3).value)

    return fixed_string


def detect_lang(text: str) -> bool:
    """
    Detects if the language is Japanese or not. Returns bool.
    """
    sanitized = re.sub("<.+?>", "", text)
    sanitized = re.sub("\n", "", sanitized)

    try:
        if langdetect.detect(sanitized) == "ja":
            return True
    except langdetect.lang_detect_exception.LangDetectException:  # Could not detect language
        return False


def read_json_file(file):
    with open(file, "r", encoding="utf-8") as json_data:
        return json.loads(json_data.read())


def convert_into_eng(word: str) -> str:
    """
    Uses the pykakasi library to phonetically convert a
    Japanese word (usually a name) into English.

    :param word: Word to convert.
    :returns: Returns up to a 10 character name in English.
    """
    kks = pykakasi.kakasi()
    invalid_chars = ["[", "]", "[", "(", ")", "\\", "/", "*", "_", "+", "?", "$", "^", '"']
    player_names = merge_jsons(["json/_lang/en/custom_player_names.json", "json/_lang/en/custom_npc_names.json"])

    result = kks.convert(word)
    romaji_name = ""
    for word in result:
        romaji_name = romaji_name + word["hepburn"]
    romaji_name = romaji_name.title()
    for item in invalid_chars:
        romaji_name = romaji_name.replace(item, "")
    for item in player_names:
        if romaji_name in player_names:
            value = player_names.get(romaji_name)
            if value:
                romaji_name = value[0:10]
                break

    return romaji_name[0:10]
