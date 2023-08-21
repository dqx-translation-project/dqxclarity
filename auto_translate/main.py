import deepl
import glob
import json
import os
import random
import re
import sys
import textwrap
import unicodedata

import requests
from alive_progress import alive_bar
from dotenv import load_dotenv

from globals import GITHUB_CLARITY_GLOSSARY_URL


def load_env():
    """
    Load global environment variables and download our glossary.
    """
    global DEEPL_KEYS
    global GLOSSARY

    load_dotenv()

    DEEPL_KEYS = [ x for x in json.loads(os.environ["DEEPL_KEYS"]) if x ]
    GLOSSARY = requests.get(GITHUB_CLARITY_GLOSSARY_URL)
    if not DEEPL_KEYS:
        print("Provide at least one key in DEEPL_KEYS.")
        sys.exit(1)
    if GLOSSARY.status_code != 200:
        print("Did not get 200 from Github glossary URL.")
        sys.exit(1)
    GLOSSARY = [ x for x in GLOSSARY.content.decode().split("\n") if x ]


def translate(text: str) -> str:
    """
    Sends text to deepl to be translated.

    :param text: Text to send to DeepL.
    :param xml_handling: Whether to tell DeepL to use xml_handling when handling tags.
    :returns: Translated text.
    """
    api_key = random.choice(DEEPL_KEYS)
    translator = deepl.Translator(api_key)

    response = translator.translate_text(
        text=text,
        source_lang="ja",
        target_lang="en-us",
        preserve_formatting=True
    )
    text_results = []
    for result in response:
        text_results.append(result.text)
    return text_results


def get_remaining_limit(api_key: str) -> int:
    """
    Returns remaining characters for a specified api key.

    :param api_key: API key to check the remaining characters of.
    :returns: Number of remaining characters.
    """
    translator = deepl.Translator(api_key)
    usage = translator.get_usage()
    remaining_chars = usage._character.limit - usage._character.count

    return remaining_chars


def get_remaining_keys_all():
    """
    Parses all keys configured in DEEPL_KEYS and returns the remaining num of characters.
    """
    for key in DEEPL_KEYS:
        remaining = get_remaining_limit(key)
        print(f"Key {key[0:5]}.. has {remaining} remaining characters.")


def glossary_replace(text: str) -> str:
    """
    Does a find/replace of all strings in the glossary against a target string.

    :param text: String that is parsed against the glossary with.
    :returns: A new string that has been passed through the glossary.
    """
    for record in GLOSSARY:
        k, v = record.split(",", 1)
        if v == "\"\"":  # check for glossary entries that have blank strings and re-assign
            v = ""
        text = text.replace(k, v)
    return text


def add_line_endings(text: str) -> str:
    """
    Adds <br> flags every 3 lines to a string. Used to break up the
    text in a dialog window.

    :param text: Text to add the <br> tags to.
    :returns: A new string with the text broken up by <br> tags.
    """
    count_list = [ i for i in range(3, 500, 4) ] # 500 is arbitrary, but we should never hit this.
    split_text = text.split("\n")
    try:
        for i in count_list:
            _ = split_text[i]
            split_text.insert(i, "<br>")
    except IndexError:
        split_text = [ x for x in split_text if x ]
        output = "\n".join(split_text)
        return output


def wrap_text(text: str) -> str:
    """
    Wrap text to 46 characters per line, which is the maximum that will
    fit in DQX's dialog window. Doesn't consider tags as characters.
    """
    return textwrap.fill(text, width=46, replace_whitespace=False)


def normalize_text(text: str) -> str:
    """
    "Normalize" text by only using latin alphabet.

    :param text: Text to normalize
    :returns: Normalized text.
    """
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()


def sanitize_text(text: str) -> str:
    """
    Sanitizes text with a series of actions to make English text
    render more comfortably in DQX. Also ensures the text is properly
    parsed before sending off to DeepL to be machine translated.

    :param text: Text to be sanitized.
    :returns: A formatted string that is ready to be inserted into our JSON format.
    """
    # manage our own line endings later
    output = text.replace("<br>", "　")

    # remove any tag alignments
    alignments = ["<center>", "<right>", "<left>"]
    for alignment in alignments:
        output = output.replace(alignment, "")

    # remove any other oddities that don't look great in english
    oddities = ["「", "…"]
    for oddity in oddities:
        output = output.replace(oddity, "")

    # remove the full width space that starts on a new line
    output = output.replace("\n　", "　")

    # replace any <color*> tags with & as they are part of the string
    output = output.replace("<color_", "<&color_")

    name_tags = ["<pc>", "<cs_pchero>", "<kyodai>"]

    # removes all of the honorifics added at the end of the tags
    honorifics = ["さま", "君", "どの", "ちゃん", "くん", "様", "さーん", "殿", "さん",]
    for tag in name_tags:
        for honorific in honorifics:
            output = output.replace(f"{tag}{honorific}", tag)

    # replace all variable name tags that expand to other text
    output = swap_placeholder_tags(output)

    # pass string through our glossary to replace any common words
    output = glossary_replace(output)

    # re-assign this string. this is now our "pristine" string we'll be using later.
    pristine_str = output

    # get the text to translate, splitting on all tags that don't start with % or &
    tag_re = re.compile("(<[^%&]*?>)")
    select_re = re.compile(r"(<select.*>)")
    str_split = [ x for x in re.split(tag_re, output) if x ]

    count = 0
    str_attrs = {}

    # iterate over each string, handling based on condition
    for str in str_split:
        if not re.match(tag_re, str):

            # sole new lines need to stay where they are.
            if str == "\n":
                continue

            # capture position of the string and replace with placeholder text
            pristine_str = pristine_str.replace(str, f"<replace_me_index_{count}>")

            # <select*> lists always start with their first entry being a newline.
            # if we see this, look back one index to see if we're inside a select tag.
            if str.startswith("\n"):
                lookback = str_split.index(str) - 1
                if re.match(select_re, str_split[lookback]):
                    str_attrs[count] = {
                        "text": str,
                        "is_list": True,
                        "prepend_newline": False,
                        "append_newline": False,
                    }
                    count += 1
                    continue

            # capture how the newline was originally placed
            append_newline = False
            if str.endswith("\n"):
                append_newline = True

            prepend_newline = False
            if str.startswith("\n"):
                prepend_newline = True

            str = str.replace("\n", "")

            str_attrs[count] = {
                "text": str,
                "is_list": False,
                "prepend_newline": prepend_newline,
                "append_newline": append_newline,
            }

            count += 1

    # translate our list of strings
    to_translate = []
    count = 0
    for str in str_attrs:
        to_translate.append(str_attrs[count]["text"])
        count += 1
    translated_list = translate(text=to_translate)

    # update our str_attrs dict with the new, translated string
    count = 0
    for str in translated_list:
        str_attrs[count]["text"] = str
        count += 1

    count = 0
    # search for any weird space usage and remove it.
    # this comes from deepl and are all scenarios that have been seen with
    # translations coming back from machine translation.
    for _ in str_attrs:
        str_text = str_attrs[count]["text"]
        str_text = str_text.replace("　 ", " ")
        str_text = str_text.replace("　", " ")
        str_text = str_text.replace("  ", "")

        updated_str = normalize_text(str_text)
        updated_str = updated_str.replace("<&color_", "<color_")  # put our color tag back.

        if str_attrs[count]["is_list"]:
            # select lists will always have more than 1 entry..
            # leave selection lists alone. please don't fuck this up, deepl
            updated_str = swap_placeholder_tags(updated_str, swap_back=True)

            # deepl occasionally indents our list lines.. even though they weren't originally indented
            updated_str = updated_str.replace("\n ", "\n")
            pristine_str = pristine_str.replace(f"<replace_me_index_{count}>", updated_str)

        else:
            # wrap the text to 46 characters and inject <br>'s to break the text up
            updated_str = wrap_text(updated_str)
            updated_str = swap_placeholder_tags(updated_str, swap_back=True)
            updated_str = add_line_endings(updated_str)
            if str_attrs[count]["prepend_newline"]:
                updated_str = "\n" + updated_str
            if str_attrs[count]["append_newline"]:
                updated_str += "\n"

            pristine_str = pristine_str.replace(f"<replace_me_index_{count}>", updated_str)

        count += 1

    return pristine_str


def swap_placeholder_tags(text: str, swap_back=False) -> str:
    if not swap_back:
        text = text.replace("<pc_hiryu>", "<&13_aaaaaaa>")
        text = text.replace("<cs_pchero_hiryu>", "<&13_aaaaaab>")
        text = text.replace("<cs_pchero_race>", "<&8_aaa>")
        text = text.replace("<cs_pchero>", "<13_aaaaaac>")
        text = text.replace("<kyodai_rel1>", "<&7_aa>")
        text = text.replace("<kyodai_rel2>", "<&7_ab>")
        text = text.replace("<kyodai_rel3>", "<&7_ac>")
        text = text.replace("<pc_hometown>", "<&8_aab>")
        text = text.replace("<pc_race>", "<&8_aac>")
        text = text.replace("<pc_rel1>", "<&7_ad>")
        text = text.replace("<pc_rel2>", "<&7_ae>")
        text = text.replace("<pc_rel3>", "<&7_af")
        text = text.replace("<kyodai>", "<&13_aaaaaac>")
        text = text.replace("<pc>", "<&13_aaaaaad>")
        text = text.replace("<client_pcname>", "<&13_aaaaaae>")
        text = text.replace("<heart>", "<&2a>")
        text = text.replace("<diamond>", "<&2b>")
        text = text.replace("<spade>", "<&2c>")
        text = text.replace("<clover>", "<&2d>")
        text = text.replace("<r_triangle>", "<&2e>")
        text = text.replace("<l_triangle>", "<&2f>")
        text = text.replace("<half_star>", "<&2g>")
        text = text.replace("<null_star>", "<&2h>")
        text = text.replace("<npc>", "<&13_aaaaaaf>")
        text = text.replace("<pc_syokugyo>", "<&13_aaaaaag>")
        text = text.replace("<pc_original>", "<&13_aaaaaah>")
        text = text.replace("<log_pc>", "<&13_aaaaaai>")
        text = text.replace("<1st_title>", "<&20_aaaaaaaaaaaaaa>")
        text = text.replace("<2nd_title>", "<&20_aaaaaaaaaaaaab>")
        text = text.replace("<3rd_title>", "<&20_aaaaaaaaaaaaac>")
        text = text.replace("<4th_title>", "<&20_aaaaaaaaaaaaad>")
        text = text.replace("<5th_title>", "<&20_aaaaaaaaaaaaae>")
        text = text.replace("<6th_title>", "<&20_aaaaaaaaaaaaaf>")
        text = text.replace("<7th_title>", "<&20_aaaaaaaaaaaaag>")
    else:
        text = text.replace("<&13_aaaaaaa>", "<pc_hiryu>")
        text = text.replace("<&13_aaaaaab>", "<cs_pchero_hiryu>")
        text = text.replace("<&8_aaa>", "<cs_pchero_race>")
        text = text.replace("<13_aaaaaac>", "<cs_pchero>")
        text = text.replace("<&7_aa>", "<kyodai_rel1>")
        text = text.replace("<&7_ab>", "<kyodai_rel2>")
        text = text.replace("<&7_ac>", "<kyodai_rel3>")
        text = text.replace("<&8_aab>", "<pc_hometown>")
        text = text.replace("<&8_aac>", "<pc_race>")
        text = text.replace("<&7_ad>", "<pc_rel1>")
        text = text.replace("<&7_ae>", "<pc_rel2>")
        text = text.replace("<&7_af", "<pc_rel3>")
        text = text.replace("<&13_aaaaaac>", "<kyodai>")
        text = text.replace("<&13_aaaaaad>", "<pc>")
        text = text.replace("<&13_aaaaaae>", "<client_pcname>")
        text = text.replace("<&2a>", "<heart>")
        text = text.replace("<&2b>", "<diamond>")
        text = text.replace("<&2c>", "<spade>")
        text = text.replace("<&2d>", "<clover>")
        text = text.replace("<&2e>", "<r_triangle>")
        text = text.replace("<&2f>", "<l_triangle>")
        text = text.replace("<&2g>", "<half_star>")
        text = text.replace("<&2h>", "<null_star>")
        text = text.replace("<&13_aaaaaaf>", "<npc>")
        text = text.replace("<&13_aaaaaag>", "<pc_syokugyo>")
        text = text.replace("<&13_aaaaaah>", "<pc_original>")
        text = text.replace("<&13_aaaaaai>", "<log_pc>")
        text = text.replace("<&20_aaaaaaaaaaaaaa>", "<1st_title>")
        text = text.replace("<&20_aaaaaaaaaaaaab>", "<2nd_title>")
        text = text.replace("<&20_aaaaaaaaaaaaac>", "<3rd_title>")
        text = text.replace("<&20_aaaaaaaaaaaaad>", "<4th_title>")
        text = text.replace("<&20_aaaaaaaaaaaaae>", "<5th_title>")
        text = text.replace("<&20_aaaaaaaaaaaaaf>", "<6th_title>")
        text = text.replace("<&20_aaaaaaaaaaaaag>", "<7th_title>")

    return text


def read_file(file: str) -> dict:
    """
    Returns data from a json file.

    :param file: File to read.
    :returns: A dict of the json data.
    """
    with open(file, "r", encoding="utf-8") as f:
        data = json.loads(f.read())
    return data


def estimate_characters(data: dict) -> int:
    characters = ""
    for id in data:
        ja = next(iter(data.get(id).keys()))
        en = data[id][ja]
        if not en:
            characters += ja
    return len(characters)


if __name__ == "__main__":
    load_env()

    for file in glob.glob("files/*"):
        get_remaining_keys_all()

        data = read_file(file)
        num_entries = len(data)
        estimated_chars = estimate_characters(data)

        print(f"Translating {os.path.basename(file)} with an estimated {estimated_chars} characters needed to be translated.")
        with alive_bar(total=num_entries, title="Translating..", theme="musical", length=20) as bar:
            for id in data:
                bar()
                ja = next(iter(data.get(id).keys()))
                en = data[id][ja]
                if not ja:
                    continue
                if not en:
                    output = sanitize_text(ja)
                    data[id][ja] = output
                    with open(file, "wb") as f:
                        f.write(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False).encode("utf-8"))

        get_remaining_keys_all()
