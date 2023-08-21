from common.errors import warning_message
from common.lib import get_abs_path, merge_jsons
from googleapiclient.discovery import build
from openpyxl import load_workbook

import configparser
import deepl
import json
import langdetect
import os
import pykakasi
import re
import shutil
import sqlite3
import textwrap
import unicodedata


class Translate():
    service = None
    api_key = None
    region_code = None
    glossary = None

    def __init__(self):
        if Translate.service is None:
            self.user_settings = load_user_config()
            self.translation_settings = determine_translation_service()
            Translate.service = self.translation_settings["TranslateService"]
            Translate.api_key = self.translation_settings["TranslateKey"]
            Translate.region_code = self.translation_settings["RegionCode"]

        if Translate.glossary is None:
            with open("/".join([get_abs_path(__file__), "../misc_files/glossary.csv"]), "r", encoding="utf-8") as f:
                strings = f.read()
                Translate.glossary = [ x for x in strings.split("\n") if x ]


    def deepl(self, text: str):
        self.region_code = Translate.region_code
        if self.region_code.lower() == "en":
            self.region_code = "en-us"
        translator = deepl.Translator(Translate.api_key)
        response = translator.translate_text(text=text, source_lang="ja", target_lang=self.region_code)
        return response.text


    def google(self, text: str):
        service = build("translate", "v2", developerKey=Translate.api_key)
        response = service.translations().list(source="ja", target="en", format="text", q=[text]).execute()
        return response["translations"][0]["translatedText"]


    def __glossify(self, text):
        for record in Translate.glossary:
            k, v = record.split(",", 1)
            if v == "\"\"":  # check for glossary entries that have blank strings and re-assign
                v = ""
            text = text.replace(k, v)
        return text


    def translate(self, text: str):
        text = self.__glossify(text)
        if Translate.service == "deepl":
            return self.deepl(text)
        if Translate.service == "google":
            return self.google(text)
        return None


def sanitized_dialog_translate(dialog_text, text_width=45, max_lines=None) -> str:
    """Does a bunch of text sanitization to handle tags seen in DQX, as well as
    automatically splitting the text up into chunks to be fed into the in-game
    dialog window."""
    translator = Translate()
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
                        translation = translator.translate(sanitized)
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
                        translation = translator.translate(sanitized)
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


def sqlite_read(text_to_query, language, table):
    """Reads text from a SQLite table."""
    escaped_text = text_to_query.replace("'", "''")

    try:
        db_file = "/".join([get_abs_path(__file__), "../misc_files/clarity_dialog.db"])
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
        db_file = "/".join([get_abs_path(__file__), "../misc_files/clarity_dialog.db"])
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


def load_user_config():
    """Returns a user's config settings. If the config doesn't exist, a default
    config is generated. If the user's config is missing values, we back up the
    old config and generate a new default one for them.

    :returns: Dict of config.
    """
    filename = "/".join([get_abs_path(__file__), "../user_settings.ini"])
    base_config = configparser.ConfigParser()
    base_config["translation"] = {
        "enabledeepltranslate": False,
        "deepltranslatekey": "",
        "enablegoogletranslate": False,
        "googletranslatekey": "",
        "regioncode": "en",
    }
    base_config["behavior"] = {"enabledialoglogging": "False"}
    base_config["config"] = {"installdirectory": ""}

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
            message=f"We found a missing config value in your {filename}.\n\nYour old config has been renamed to {filename}.invalid in case you need to reference it.\n\nPlease relaunch dqxclarity.",
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
    """Updates an existing configuration option in a user's config.

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
    """Parses the user_settings file to get information needed to make
    translation calls."""
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
    """Searches for a string from the specified json file and either returns
    the string or returns False if no match found.

    text: The text to search
    file: The name of the file (leave off the file extension)
    """
    misc_files = "/".join([get_abs_path(__file__), "../misc_files"])
    data = read_json_file(misc_files + "/" + file + ".json")

    for item in data:
        key, value = list(data[item].items())[0]
        if re.search(f"^{text}+$", key):
            if value:
                return value


def clean_up_and_return_items(text: str) -> str:
    """Cleans up unnecessary text from item strings and searches for the name
    in items.json.

    Used specifically for the quest window.
    """
    misc_files = "/".join([get_abs_path(__file__), "../misc_files"])
    quest_rewards = merge_jsons([
        f"{misc_files}/subPackage41Client.win32.json",
        f"{misc_files}/subPackage05Client.json",
        f"{misc_files}/custom_quest_rewards.json"
    ])
    line_count = text.count("\n")
    sanitized = re.sub("男は ", "", text)  # remove boy reference from start of string
    sanitized = re.sub("女は ", "", sanitized)  # remove girl reference from start of string
    sanitized = re.sub("男は　", "", sanitized)  # remove boy reference from start of string (fullwidth space)
    sanitized = re.sub("女は　", "", sanitized)  # remove girl reference from start of string (fullwidth space)
    sanitized = re.sub("！　と頼まれた。", "と頼まれた。", sanitized)  # remove annoying 'asked to' string
    final_string = ""
    for item in sanitized.split("\n"):
        quantity = ""
        no_bullet = re.sub("(^\・)", "", item)
        points = no_bullet[6:18]
        if no_bullet.endswith("こ"):
            quantity = "(" + unicodedata.normalize("NFKC", no_bullet[-3:-1]) + ")"
            quantity = re.sub(" ", "", quantity)
        if no_bullet.endswith("他"):
            bad_strings = ["必殺技を覚える", "入れられるよう"]
            if any(string in no_bullet for string in bad_strings):
                quantity = ""
            else:
                quantity = "(1)"
        no_bullet = re.sub("(　　.*)", "", no_bullet)
        if no_bullet in quest_rewards:
            value = quest_rewards.get(no_bullet)
            if value:
                value_length = len(value)
                quant_length = len(quantity)
                byte_count = len(value.encode('utf-8'))
                num_spaces = 31 - value_length - quant_length - ((byte_count - value_length)//2)
                if "・" in item:
                    if line_count == 0:
                        return "・" + value + (" " * num_spaces) + quantity
                    else:
                        final_string += "・" + value + (" " * num_spaces) + quantity + "\n"
                else:
                    if line_count == 0:
                        return value + (" " * num_spaces) + quantity
                    else:
                        final_string += value + (" " * num_spaces) + quantity + "\n"
        else:
            if line_count == 0:
                if "討伐ポイント" in item:
                    return "・" + "Experience Points" + points
                else:
                    return text
            else:
                final_string += item + "\n"
    return final_string.rstrip()


def deal_with_icky_strings(text) -> str:
    fixed_string = ""
    file = "/".join([get_abs_path(__file__), "../misc_files/merge.xlsx"])
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
    """Detects if the language is Japanese or not.

    Returns bool.
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
    """Uses the pykakasi library to phonetically convert a Japanese word
    (usually a name) into English.

    :param word: Word to convert.
    :returns: Returns up to a 10 character name in English.
    """
    kks = pykakasi.kakasi()
    invalid_chars = ["[", "]", "[", "(", ")", "\\", "/", "*", "_", "+", "?", "$", "^", '"']
    misc_files = "/".join([get_abs_path(__file__), "../misc_files"])
    player_names = merge_jsons([f"{misc_files}/custom_player_names.json", f"{misc_files}/custom_npc_names.json"])
    interpunct_count = word.count("・")
    word_len = len(word)
    bad_word = False

    if any(char in word for char in invalid_chars):
        return word
    else:
        romaji_name = ""
        if word in player_names:
            value = player_names.get(word)
            if value:
                romaji_name = value
            return romaji_name[0:10]
        else:
            if word_len < 7:
                for char in word:
                    num = ord(char)
                    if num not in (list(range(12353, 12430)) + [12431] + list(range(12434,12436)) + list(range(12449,12526)) + [12527] + list(range(12530,12533)) + list(range(12539,12541)) + [65374]):
                        bad_word = True
                        return word
                if bad_word != True:
                    result = kks.convert(word)
                    for word in result:
                        romaji_name = romaji_name + word["hepburn"]
                    romaji_name = romaji_name.title()
                    romaji_name = romaji_name.replace("・", "")
                    if romaji_name == "":
                        romaji_name = "." * interpunct_count
                    return romaji_name[0:10]
            else:
                return word
