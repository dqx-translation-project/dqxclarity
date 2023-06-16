import deepl
import os
import random
import sys
import textwrap
import unicodedata
import json
import re
import requests
from alive_progress import alive_bar
from dotenv import load_dotenv
from globals import GITHUB_CLARITY_GLOSSARY_URL


def load_env():
    global DEEPL_KEYS
    global FILES_TO_TRANSLATE
    global GLOSSARY

    load_dotenv()

    DEEPL_KEYS = [ x for x in json.loads(os.environ["DEEPL_KEYS"]) if x ]
    FILES_TO_TRANSLATE = [ x for x in json.loads(os.environ["FILES_TO_TRANSLATE"]) if x ]
    GLOSSARY = requests.get(GITHUB_CLARITY_GLOSSARY_URL)
    if not DEEPL_KEYS:
        print("Provide at least one key in DEEPL_KEYS.")
        sys.exit(1)
    if not FILES_TO_TRANSLATE:
        print("Provide at least one file in FILES_TO_TRANSLATE.")
        sys.exit(1)
    if GLOSSARY.status_code != 200:
        print("Did not get 200 from Github glossary URL.")
        sys.exit(1)
    GLOSSARY = [ x for x in GLOSSARY.content.decode().split("\n") if x ]


def translate(text: str) -> str:
    api_key = random.choice(DEEPL_KEYS)
    translator = deepl.Translator(api_key)
    response = translator.translate_text(
        text=text,
        source_lang="ja",
        target_lang="en-us",
        formality="prefer_less"
    )
    return response.text


def get_remaining_limit(api_key: str) -> int:
    translator = deepl.Translator(api_key)
    usage = translator.get_usage()
    remaining_chars = usage._character.limit - usage._character.count

    return remaining_chars


def glossary_replace(text: str):
    for record in GLOSSARY:
        k, v = record.split(",", 1)
        if v == "\"\"":  # check for glossary entries that have blank strings and re-assign
            v = ""
        text = text.replace(k, v)
    return text


def add_line_endings(text: str):
    count_list = [3, 7, 11, 15, 19, 23, 27, 31, 35, 39]
    split_text = text.split("\n")
    try:
        for i in count_list:
            _ = split_text[i]
            split_text.insert(i, "<br>")
    except IndexError:
        split_text = [ x for x in split_text if x ]
        output = "\n".join(split_text)
        return output
    return text


def sanitize_text(text: str) -> str:
    # manage our own line endings later
    output = re.sub("<br>", "　", text)

    # ensures that when these tags are expanded to their actual names,
    # we have appropriate room in the dialog window.
    output = re.sub("<pc>", "<pplaceholdc>", output)
    output = re.sub("<cs_pchero>", "<cplaceholds>", output)
    output = re.sub("<kyodai>", "<kplaceholdy>", output)

    # remove any tag alignments
    alignments = ["<center>", "<right>", "<left>"]
    for alignment in alignments:
        output = re.sub(alignment, "", output)

    # remove any other oddities that don't look great in english
    output = re.sub("「", "", output) # creates a single double quote
    output = re.sub("…", "", output)

    # remove the full width space that starts on a new line
    output = re.sub("\n　", "　", output)

    # handle selection lists. we don't want to remove the newlines from them
    # as they need to be translated individually.
    select_regex = re.compile(r"(<select.*>)")
    find_select = select_regex.findall(output)
    if find_select:
        found_select_tag = find_select[0]
        output = output.split(found_select_tag)
        output[0] = output[0].rstrip() + "\n"
        output = found_select_tag.join(output)
    else:
        output = output.replace("\n", "")

    # <pc>, <cs_pchero>, <kyodai>
    placeholder_tags = ["<pplaceholdc>", "<cplaceholds>", "<kplaceholdy>"]

    # removes all of the honorifics added at the end of the tags
    honorifics = ["さま", "君", "どの", "ちゃん", "くん", "様", "さーん", "殿", "さん"]
    for tag in placeholder_tags:
        for honorific in honorifics:
            output = re.sub(f"{tag}{honorific}", tag, output)

    # pass string through our glossary and send to deepl
    output = glossary_replace(output)
    output = translate(output)

    # add our line endings here. before we do, we need to chop the string up
    # again in case we have a selection list.
    if find_select:
        output = output.split(found_select_tag)
        output[0] = textwrap.fill(output[0], width=46, replace_whitespace=False)
        output[0] = add_line_endings(output[0])
        output[0] = output[0] + "\n"
        output = found_select_tag.join(output)
    else:
        output = textwrap.fill(output, width=46, replace_whitespace=False)
        output = add_line_endings(output)

    # replace the placeholder tags inserted earlier with the proper tags
    # replace accented characters as the game can't handle them
    output = re.sub("<pplaceholdc>", "<pc>", output)
    output = re.sub("<cplaceholds>", "<cs_pchero>", output)
    output = re.sub("<kplaceholdy>", "<kyodai>", output)

    # "normalize" string by removing non-latin characters from the string
    output = unicodedata.normalize("NFKD", output).encode("ascii", "ignore").decode()

    return output


def read_file(file: str):
    with open(file, "r", encoding="utf-8") as f:
        data = json.loads(f.read())
    return data


if __name__ == "__main__":
    load_env()

    for file in FILES_TO_TRANSLATE:
        data = read_file(f"files/{file}")
        num_entries = len(data)

        with alive_bar(total=num_entries, title="Translating..", theme="musical", length=20) as bar:
            for id in data:
                bar()
                ja = next(iter(data.get(id).keys()))
                en = data[id][ja]
                if not en:
                    output = sanitize_text(ja)
                    data[id][ja] = output
                    with open(file, "wb") as f:
                        f.write(
                            json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False).encode("utf-8")
                        )
