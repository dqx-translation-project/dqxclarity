import langdetect
import pykakasi
import re
import textwrap
import unicodedata
from common.config import UserConfig
from common.db_ops import generate_glossary_dict, generate_m00_dict, init_db
from common.translators.deepl import DeepLTranslate
from common.translators.googletranslate import GoogleTranslate
from common.translators.googletranslatefree import GoogleTranslateFree
from functools import cache
from loguru import logger as log


# module constants to prevent re-initialization each run.
_INVALID_CHARS = frozenset(["[", "]", "(", ")", "\\", "/", "*", "_", "+", "?", "$", "^", '"'])
_HIRAGANA_CODEPOINTS = frozenset(list(range(12353, 12430)) + [12431] + list(range(12434, 12436)))
_KATAKANA_CODEPOINTS = frozenset(
    list(range(12449, 12526)) + [12527] + list(range(12530, 12533)) + list(range(12539, 12541)) + [65374]
)
_VALID_CODEPOINTS = _HIRAGANA_CODEPOINTS | _KATAKANA_CODEPOINTS

_KKS = pykakasi.kakasi()


class Translator:
    service = None
    api_key = None
    glossary = None

    def __init__(self):
        if Translator.service is None:
            self.user_settings = UserConfig()
            Translator.service = self.user_settings.translate_service
            Translator.api_key = self.user_settings.translate_key

        if Translator.glossary is None:
            Translator.glossary = generate_glossary_dict()

    def __glossify(self, text):
        for ja in Translator.glossary:
            en = Translator.glossary[ja]

            # use leading and trailing spaces in case two words are replaced back to back.
            text = text.replace(ja, f" {en} ")

        # if two strings are replaced back to back, they will have a double space.
        text = text.replace("  ", " ")
        text = text.lstrip()

        return text

    def __normalize_text(self, text: str) -> str:
        """ "Normalize" text by only using latin alphabet.

        :param text: Text to normalize
        :returns: Normalized text.
        """
        return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()

    def __swap_placeholder_tags(self, text: str, swap_back=False) -> str:
        if not swap_back:
            text = text.replace("<pc_hiryu>", "<&13_aaaaaaa>")
            text = text.replace("<cs_pchero_hiryu>", "<&13_aaaaaab>")
            text = text.replace("<cs_pchero_race>", "<&8_aaa>")
            text = text.replace("<cs_pchero>", "<&13_aaaaaac>")
            text = text.replace("<kyodai_rel1>", "<&7_aa>")
            text = text.replace("<kyodai_rel2>", "<&7_ab>")
            text = text.replace("<kyodai_rel3>", "<&7_ac>")
            text = text.replace("<pc_hometown>", "<&8_aab>")
            text = text.replace("<pc_race>", "<&8_aac>")
            text = text.replace("<%sM_real_race>", "<&8_aad>")
            text = text.replace("<pc_rel1>", "<&7_ad>")
            text = text.replace("<pc_rel2>", "<&7_ae>")
            text = text.replace("<pc_rel3>", "<&7_af>")
            text = text.replace("<kyodai>", "<&13_aaaaaad>")
            text = text.replace("<pc>", "<&13_aaaaaae>")
            text = text.replace("<client_pcname>", "<&13_aaaaaaf>")
            text = text.replace("<heart>", "<&2a>")
            text = text.replace("<diamond>", "<&2b>")
            text = text.replace("<spade>", "<&2c>")
            text = text.replace("<clover>", "<&2d>")
            text = text.replace("<r_triangle>", "<&2e>")
            text = text.replace("<l_triangle>", "<&2f>")
            text = text.replace("<half_star>", "<&2g>")
            text = text.replace("<null_star>", "<&2h>")
            text = text.replace("<npc>", "<&13_aaaaaag>")
            text = text.replace("<pc_syokugyo>", "<&13_aaaaaah>")
            text = text.replace("<pc_original>", "<&13_aaaaaai>")
            text = text.replace("<log_pc>", "<&13_aaaaaaj>")
            text = text.replace("<%sM_NAME>", "<&13_aaaaaak>")
            text = text.replace("<%sM_BEFORE_NAME>", "<&13_aaaaaal>")
            text = text.replace("<%sM_OWNER_OTHER>", "<&13_aaaaaam>")
            text = text.replace("<%sM_OWNER>", "<&13_aaaaaan>")
            text = text.replace("<%sM_SAMA>", "<&6_a>")
            text = text.replace("<1st_title>", "<&20_aaaaaaaaaaaaaa>")
            text = text.replace("<2nd_title>", "<&20_aaaaaaaaaaaaab>")
            text = text.replace("<3rd_title>", "<&20_aaaaaaaaaaaaac>")
            text = text.replace("<4th_title>", "<&20_aaaaaaaaaaaaad>")
            text = text.replace("<5th_title>", "<&20_aaaaaaaaaaaaae>")
            text = text.replace("<6th_title>", "<&20_aaaaaaaaaaaaaf>")
            text = text.replace("<7th_title>", "<&20_aaaaaaaaaaaaag>")
        else:
            text = text.replace("<&13_aaaaaaaa>", "<pc_hiryu>")
            text = text.replace("<&13_aaaaaaa>", "<pc_hiryu>")
            text = text.replace("<&13_aaaaaa>", "<pc_hiryu>")
            text = text.replace("<&13_aaaaaaab>", "<cs_pchero_hiryu>")
            text = text.replace("<&13_aaaaaab>", "<cs_pchero_hiryu>")
            text = text.replace("<&13_aaaaab>", "<cs_pchero_hiryu>")
            text = text.replace("<&8_aaa>", "<cs_pchero_race>")
            text = text.replace("<&13_aaaaaaac>", "<cs_pchero>")
            text = text.replace("<&13_aaaaaac>", "<cs_pchero>")
            text = text.replace("<&13_aaaaac>", "<cs_pchero>")
            text = text.replace("<&7_aa>", "<kyodai_rel1>")
            text = text.replace("<&7_ab>", "<kyodai_rel2>")
            text = text.replace("<&7_ac>", "<kyodai_rel3>")
            text = text.replace("<&8_aab>", "<pc_hometown>")
            text = text.replace("<&8_aac>", "<pc_race>")
            text = text.replace("<&8_aad>", "<%sM_real_race>")
            text = text.replace("<&7_ad>", "<pc_rel1>")
            text = text.replace("<&7_ae>", "<pc_rel2>")
            text = text.replace("<&7_af>", "<pc_rel3>")
            text = text.replace("<&13_aaaaaaad>", "<kyodai>")
            text = text.replace("<&13_aaaaaad>", "<kyodai>")
            text = text.replace("<&13_aaaaad>", "<kyodai>")
            text = text.replace("<&13_aaaaaaae>", "<pc>")
            text = text.replace("<&13_aaaaaae>", "<pc>")
            text = text.replace("<&13_aaaaae>", "<pc>")
            text = text.replace("<&13_aaaaaaaf>", "<client_pcname>")
            text = text.replace("<&13_aaaaaaf>", "<client_pcname>")
            text = text.replace("<&13_aaaaaf>", "<client_pcname>")
            text = text.replace("<&2a>", "<heart>")
            text = text.replace("<&2b>", "<diamond>")
            text = text.replace("<&2c>", "<spade>")
            text = text.replace("<&2d>", "<clover>")
            text = text.replace("<&2e>", "<r_triangle>")
            text = text.replace("<&2f>", "<l_triangle>")
            text = text.replace("<&2g>", "<half_star>")
            text = text.replace("<&2h>", "<null_star>")
            text = text.replace("<&13_aaaaaaag>", "<npc>")
            text = text.replace("<&13_aaaaaag>", "<npc>")
            text = text.replace("<&13_aaaaag>", "<npc>")
            text = text.replace("<&13_aaaaaaah>", "<pc_syokugyo>")
            text = text.replace("<&13_aaaaaah>", "<pc_syokugyo>")
            text = text.replace("<&13_aaaaah>", "<pc_syokugyo>")
            text = text.replace("<&13_aaaaaaai>", "<pc_original>")
            text = text.replace("<&13_aaaaaai>", "<pc_original>")
            text = text.replace("<&13_aaaaai>", "<pc_original>")
            text = text.replace("<&13_aaaaaaaj>", "<log_pc>")
            text = text.replace("<&13_aaaaaaj>", "<log_pc>")
            text = text.replace("<&13_aaaaaj>", "<log_pc>")
            text = text.replace("<&13_aaaaaaak>", "<%sM_NAME>")
            text = text.replace("<&13_aaaaaak>", "<%sM_NAME>")
            text = text.replace("<&13_aaaaak>", "<%sM_NAME>")
            text = text.replace("<&13_aaaaaaal>", "<%sM_BEFORE_NAME>")
            text = text.replace("<&13_aaaaaal>", "<%sM_BEFORE_NAME>")
            text = text.replace("<&13_aaaaal>", "<%sM_BEFORE_NAME>")
            text = text.replace("<&13_aaaaaaam>", "<%sM_OWNER_OTHER>")
            text = text.replace("<&13_aaaaaam>", "<%sM_OWNER_OTHER>")
            text = text.replace("<&13_aaaaam>", "<%sM_OWNER_OTHER>")
            text = text.replace("<&13_aaaaaaan>", "<%sM_OWNER>")
            text = text.replace("<&13_aaaaaan>", "<%sM_OWNER>")
            text = text.replace("<&13_aaaaan>", "<%sM_OWNER>")
            text = text.replace("<&6_a>", "<%sM_SAMA>")
            text = text.replace("<&20_aaaaaaaaaaaaaaa>", "<1st_title>")
            text = text.replace("<&20_aaaaaaaaaaaaaa>", "<1st_title>")
            text = text.replace("<&20_aaaaaaaaaaaaa>", "<1st_title>")
            text = text.replace("<&20_aaaaaaaaaaaaaab>", "<2nd_title>")
            text = text.replace("<&20_aaaaaaaaaaaaab>", "<2nd_title>")
            text = text.replace("<&20_aaaaaaaaaaaab>", "<2nd_title>")
            text = text.replace("<&20_aaaaaaaaaaaaaac>", "<3rd_title>")
            text = text.replace("<&20_aaaaaaaaaaaaac>", "<3rd_title>")
            text = text.replace("<&20_aaaaaaaaaaaac>", "<3rd_title>")
            text = text.replace("<&20_aaaaaaaaaaaaaad>", "<4th_title>")
            text = text.replace("<&20_aaaaaaaaaaaaad>", "<4th_title>")
            text = text.replace("<&20_aaaaaaaaaaaad>", "<4th_title>")
            text = text.replace("<&20_aaaaaaaaaaaaaae>", "<5th_title>")
            text = text.replace("<&20_aaaaaaaaaaaaae>", "<5th_title>")
            text = text.replace("<&20_aaaaaaaaaaaae>", "<5th_title>")
            text = text.replace("<&20_aaaaaaaaaaaaaaf>", "<6th_title>")
            text = text.replace("<&20_aaaaaaaaaaaaaf>", "<6th_title>")
            text = text.replace("<&20_aaaaaaaaaaaaf>", "<6th_title>")
            text = text.replace("<&20_aaaaaaaaaaaaaag>", "<7th_title>")
            text = text.replace("<&20_aaaaaaaaaaaaag>", "<7th_title>")
            text = text.replace("<&20_aaaaaaaaaaaag>", "<7th_title>")

        return text

    def __wrap_text(self, text: str, width: int, max_lines=None) -> str:
        """Wrap text to n characters per line."""
        return textwrap.fill(text, width=width, max_lines=max_lines, replace_whitespace=False)

    def __add_line_endings(self, text: str) -> str:
        """Adds <br> flags every 3 lines to a string. Used to break up the text
        in a dialog window.

        :param text: Text to add the <br> tags to.
        :returns: A new string with the text broken up by <br> tags.
        """
        count_list = [i for i in range(3, 500, 4)]  # 500 is arbitrary, but we should never hit this.
        split_text = text.split("\n")
        try:
            for i in count_list:
                _ = split_text[i]
                split_text.insert(i, "<br>")
        except IndexError:
            split_text = [x for x in split_text if x]
            output = "\n".join(split_text)
            return output

    def __api_translate(self, text: list) -> list:
        """Translates a list of strings, passing them through our glossary
        first.

        :param text: List of text strings to be translated.
        :returns: A translated list of strings in the same order they
            were given.
        """
        count = 0
        for i in text:
            text[count] = self.__glossify(i)
            count += 1
        if Translator.service == "deepl":
            translator = DeepLTranslate(Translator.api_key)
            return translator.translate(text)
        elif Translator.service == "google":
            translator = GoogleTranslate(Translator.api_key)
            return translator.translate(text)
        elif Translator.service == "googlefree":
            translator = GoogleTranslateFree()
            return translator.translate(text)
        else:
            log.exception("Invalid translation service specified in user config.")

    def translate(self, text: str, wrap_width: int, max_lines=None, add_brs=True):
        """Sanitizes different tags and symbols, then translates the string.

        :param text: String to be translated.
        :param wrap_width: How many characters the returning string
                should contain per line.
        :param max_lines: The maximum amount of lines to return. Extra
                lines are truncated with "..."
        :param add_brs: Whether to inject "<br>" every three lines to
                break up text. Used for dialog mainly.
        """
        log.debug(f"[Original]\n{text}")

        # manage our own line endings later
        output = text.replace("<br>", "　")

        # remove any tag alignments
        alignments = ["<center>", "<right>", "<left>"]
        for alignment in alignments:
            output = output.replace(alignment, "")

        # trim multiple ellipses to a single one
        ellipses = [
            "…………………………………………",
            "………………………………………",
            "……………………………………",
            "…………………………………",
            "………………………………",
            "……………………………",
            "…………………………",
            "………………………",
            "……………………",
            "…………………",
            "………………",
            "……………",
            "…………",
            "………",
            "……",
        ]
        for ellipse in ellipses:
            output = output.replace(ellipse, "…")

        # remove any other oddities that don't look great in english
        oddities = ["「", "～", "♪"]
        for oddity in oddities:
            output = output.replace(oddity, "")

        # "。" is a Japanese period, but we're seeing unwanted behavior when mixing other characters with it
        output = output.replace("…。", ".")
        output = output.replace("。", ".")

        # remove the full width space that starts on a new line
        output = output.replace("\n　", "\n")

        # replace any <color*> tags with & as they are part of the string
        output = output.replace("<color_", "<&color_")

        # removes all of the honorifics added at the end of the tags
        name_tags = ["<pc>", "<cs_pchero>", "<kyodai>"]
        honorifics = ["さま", "君", "どの", "ちゃん", "くん", "様", "さーん", "殿", "さん"]
        for tag in name_tags:
            for honorific in honorifics:
                output = output.replace(f"{tag}{honorific}", tag)

        # replace all variable name tags that expand to other text
        output = self.__swap_placeholder_tags(output)

        # pass string through our glossary to replace any common words
        output = self.__glossify(output)

        # re-assign this string. this is now our "pristine" string we'll be using later.
        pristine_str = output

        # get the text to translate, splitting on all tags that don't start with % or &
        tag_re = re.compile("(<[^%&]*?>)")
        select_re = re.compile(r"(<select.*>)")
        str_split = [x for x in re.split(tag_re, output) if x]

        count = 0
        str_attrs = {}

        # iterate over each string, handling based on condition
        for string in str_split:
            if not re.match(tag_re, string):
                # sole new lines need to stay where they are.
                if string == "\n":
                    continue

                # capture position of the string and replace with placeholder text
                pristine_str = pristine_str.replace(string, f"<replace_me_index_{count}>")

                # <select*> lists always start with their first entry being a newline.
                # if we see this, look back one index to see if we're inside a select tag.
                if string.startswith("\n"):
                    lookback = str_split.index(string) - 1
                    if re.match(select_re, str_split[lookback]):
                        str_attrs[count] = {
                            "text": string,
                            "is_list": True,
                            "prepend_newline": False,
                            "append_newline": False,
                        }
                        count += 1
                        continue

                # capture how the newline was originally placed
                append_newline = False
                if string.endswith("\n"):
                    append_newline = True

                prepend_newline = False
                if string.startswith("\n"):
                    prepend_newline = True

                string = string.replace("\n", "")
                string = string.strip()

                str_attrs[count] = {
                    "text": string,
                    "is_list": False,
                    "prepend_newline": prepend_newline,
                    "append_newline": append_newline,
                }

                count += 1

        # translate our list of strings
        to_translate = []
        count = 0
        for i in str_attrs:
            # dqx <select> lists are always at the end of the string. we'll append all list items
            # to the end of our python list so we can pass them to the translation service individually.
            if not str_attrs[count]["is_list"]:
                to_translate.append(str_attrs[count]["text"])
            else:
                for line in str_attrs[count]["text"].splitlines():
                    if line:
                        to_translate.append(line)
            count += 1

        log.debug(f"[Post-glossary]\n{to_translate}")
        translated_list = self.__api_translate(text=to_translate)
        log.debug(f"[Post-translated]\n{translated_list}")

        if not translated_list or len(translated_list) != len(to_translate):
            log.exception(f"{self.service} translation failed.")
            return ""

        # update our str_attrs dict with the new, translated string
        count = 0
        for i in translated_list:
            if not str_attrs[count]["is_list"]:
                str_attrs[count]["text"] = i
            else:
                joined_list = "\n".join(translated_list[count:])
                str_attrs[count]["text"] = joined_list + "\n"
                # lists are the last strings in dialogue, so we don't need to
                # parse anymore once we've found one.
                break
            count += 1

        count = 0
        # search for any weird space usage and remove it.
        # this comes from deepl and are all scenarios that have been seen with
        # translations coming back from machine translation.
        for _ in str_attrs:
            str_text = str_attrs[count]["text"]
            str_text = str_text.replace("　 ", " ")
            str_text = str_text.replace(" 　", " ")
            str_text = str_text.replace("　", " ")
            str_text = str_text.replace("  ", " ")
            str_text = str_text.replace("..................", "...")
            str_text = str_text.replace("...............", "...")
            str_text = str_text.replace("............", "...")
            str_text = str_text.replace(".........", "...")
            str_text = str_text.replace("......", "...")
            str_text = str_text.replace("....", "...")

            # game doesn't render em-dash. we use the Japanese "ー" instead to simulate one.
            updated_str = str_text.replace("—", "--")
            updated_str = self.__normalize_text(updated_str)
            updated_str = updated_str.replace("<&color_", "<color_")  # put our color tag back.

            if str_attrs[count]["is_list"]:
                # select lists will always have more than 1 entry..
                # leave selection lists alone. please don't fuck this up, deepl
                updated_str = self.__swap_placeholder_tags(updated_str, swap_back=True)

                # deepl occasionally indents our list lines.. even though they weren't originally indented
                updated_str = updated_str.replace("\n ", "\n")
                updated_str = updated_str.replace("\n　", "\n")
                pristine_str = pristine_str.replace(f"<replace_me_index_{count}>", updated_str)

            else:
                # wrap the text and inject <br>'s to break the text up
                updated_str = self.__wrap_text(updated_str, width=wrap_width, max_lines=max_lines)
                updated_str = self.__swap_placeholder_tags(updated_str, swap_back=True)

                if add_brs:
                    updated_str = self.__add_line_endings(updated_str)
                if str_attrs[count]["prepend_newline"]:
                    updated_str = "\n" + updated_str
                if str_attrs[count]["append_newline"]:
                    updated_str += "\n"

                # if we see a voice line tag (<voice_nw>), a <br> must exist at the end of the string no matter what.
                # this is required to make the dialog pause while the voice line continues.
                voice_re = re.compile("<voice.*>")

                # unfortunately, this rule does not apply if it belongs to a voiced cutscene in
                # Asfeld. For some reason, these dialog boxes are handled differently, but all Asfeld
                # cutscenes have a specific voice tag of <voice_nw IEV_GS####_# ##>. If we see one, don't include a <br>
                # tag in that string at all.

                if re.search(voice_re, pristine_str) and "IEV_GS" not in pristine_str:
                    tag_list = re.findall(tag_re, pristine_str)

                    # get the current index from our pristine_str
                    cur_index = tag_list.index(f"<replace_me_index_{count}>")

                    # don't add a <br> to the very last line. subtract 1 as length doesn't start at 0 like index does.
                    if len(tag_list) - 1 != cur_index:
                        # get the index of the previous string to read
                        lookback_index = cur_index - 1

                        # make sure we get a valid number before checking the index
                        if lookback_index > -1:
                            if re.match(voice_re, tag_list[lookback_index]):
                                # don't add a <br> if it already exists
                                if not updated_str.endswith("<br>"):
                                    updated_str += "<br>\n"

                pristine_str = pristine_str.replace(f"<replace_me_index_{count}>", updated_str)

            count += 1

        log.debug(f"[Final]\n{pristine_str}")
        return pristine_str


def clean_up_and_return_items(text: str) -> str:
    """Cleans up unnecessary text from item strings and searches for the name
    in items.json.

    Used specifically for the quest window.
    """
    quest_rewards = generate_m00_dict(files="'custom_quest_rewards', 'items', 'key_items'")

    line_count = text.count("\n")
    sanitized = re.sub("男は ", "", text)  # remove boy reference from start of string
    sanitized = re.sub("女は ", "", sanitized)  # remove girl reference from start of string
    sanitized = re.sub("男は　", "", sanitized)  # remove boy reference from start of string (fullwidth space)
    sanitized = re.sub("女は　", "", sanitized)  # remove girl reference from start of string (fullwidth space)
    final_string = ""
    for item in sanitized.split("\n"):
        quantity = ""
        no_bullet = re.sub(r"(^\・)", "", item)
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
                byte_count = len(value.encode("utf-8"))
                num_spaces = 31 - value_length - quant_length - ((byte_count - value_length) // 2)
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


def detect_lang(text: str) -> bool:
    """Detects if the language is Japanese or not.

    :param text: Text to check against.
    :returns: True if text is Japanese.
    """
    sanitized = re.sub("<.+?>", "", text)
    sanitized = re.sub("\n", "", sanitized)

    try:
        if langdetect.detect(sanitized) == "ja":
            return True
    except langdetect.lang_detect_exception.LangDetectException:  # Could not detect language
        return False


# infinitely cache player names as we come across them. honestly shouldn't
# be a problem as these are just small strings. we only need to capture a
# unique name once per session, then we'll just re-use.
@cache
def transliterate_player_name(word: str) -> str:
    """Uses the pykakasi library to phonetically convert a Japanese word into
    English.

    :param word: Word to convert.
    :returns: Returns up to a 10 character name in English.
    """
    # dqx character names are limited to 6 characters. if we receive something longer
    # than 6 characters, just return the word.
    if len(word) > 6:
        return word

    # check for invalid characters
    if set(word) & _INVALID_CHARS:
        return word

    # validate all characters are hiragana/katakana
    if not all(ord(char) in _VALID_CODEPOINTS for char in word):
        return word

    # use constant kakasi instance for conversion
    result = _KKS.convert(word)
    romaji = "".join([char["hepburn"] for char in result]).title().replace("・", "")

    # a player can name themselves "・". since we replace all instances of this, romaji
    # could be blank. if this is the case, we'll keep the same number of interpunct chars
    # and replace them with periods.
    if not romaji:
        romaji = "." * word.count("・")

    return romaji[0:10]


def get_player_name() -> tuple:
    """Queries the player and sibling name from the database.

    Returns a tuple of (player_name, sibling_name).
    """
    conn, cursor = init_db()

    player_query = "SELECT name FROM player WHERE type = 'player'"
    sibling_query = "SELECT name FROM player WHERE type = 'sibling'"

    results = cursor.execute(player_query)
    player = results.fetchone()[0]

    results = cursor.execute(sibling_query)
    sibling = results.fetchone()[0]

    conn.close()

    return (player, sibling)
