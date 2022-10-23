import textwrap
import json
import random
import re
import requests
from alive_progress import alive_bar


def deepl_translate(dialog_text, is_pro, api_key, region_code):
    """Uses DeepL Translate to translate text to the specified language."""
    if is_pro == "True":
        api_url = "https://api.deepl.com/v2/translate"
    else:
        api_url = "https://api-free.deepl.com/v2/translate"
    payload = {"auth_key": api_key, "text": dialog_text, "target_lang": region_code}
    while True:
        try:
            r = requests.post(api_url, data=payload, timeout=20)
            translated_text = r.content
            return json.loads(translated_text)["translations"][0]["text"]
        except:
            continue


def google_translate(dialog_text, api_key, region_code):
    """Uses Google Translate to translate text to the specified language."""
    uri = "&source=ja&target=" + region_code + "&q=" + dialog_text + "&format=text"
    api_url = "https://www.googleapis.com/language/translate/v2?key=" + api_key + uri
    headers = {"Content-Type": "application/json"}

    r = requests.post(api_url, headers=headers, timeout=5)
    translated_text = r.content

    return json.loads(translated_text)["data"]["translations"][0]["translatedText"]


def translate(translation_service, is_pro, dialog_text, api_key, region_code):
    if translation_service == "deepl":
        return deepl_translate(dialog_text, is_pro, api_key, region_code)
    elif translation_service == "google":
        return google_translate(dialog_text, api_key, region_code)


def sanitized_dialog_translate(translation_service, is_pro, dialog_text, api_key, region_code) -> str:
    """
    Does a bunch of text sanitization to handle tags seen in DQX, as well as automatically
    splitting the text up into chunks.
    """
    output = re.sub("<br>", " ", dialog_text)
    output = re.sub("<pc>", "Placeholderpcname", output)
    output = re.sub("<cs_pchero>", "Placeholdercsname", output)
    output = re.sub("<kyodai>", "Placeholderkyname", output)
    output = re.split("(<(?!%).+?>)", output)
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
            "<left>",
        ]  # center and right aligned text doesn't work well in this game with ascii. left is useless
        if item in alignment:
            final_string += ""
            continue
        if re.search("(<(?!%).+?>)", item):  # don't capture variable tags. ex: <%nC_GOLD>
            item = re.sub("<select>", "|<select>", item)
            item = re.sub("<select_nc>", "|<select_nc>", item)
            item = re.sub("<select_se_off>", "|<select_se_off>", item)
            item = re.sub("<select_se_off 2>", "|<select_se_off 2>", item)
            item = re.sub("<select_se_off 3>", "|<select_se_off 3>", item)
            item = re.sub("<select_se_off 5>", "|<select_se_off 5>", item)
            item = re.sub("<se_nots System 7>", "|<se_nots System 7>", item)
            item = re.sub("<se_nots System 17>", "|<se_nots System 17>", item)
            final_string += item
        else:
            # lists don't have puncuation. remove new lines before sending to translate
            puncs = ["。", "？", "！"]
            if any(x in item for x in puncs):
                # pre process before translation
                sanitized = re.sub("\n", " ", item) + "\n"
                sanitized = re.sub("\u3000", "", sanitized)  # replace full width spaces with ascii spaces
                sanitized = re.sub(
                    "「", "", sanitized
                )  # these create a single double quote, which look weird in english
                sanitized = re.sub("...。", "。", sanitized)  # don't add japanese period to ascii period
                sanitized = re.sub("…。", "。", sanitized)  # don't add japanese period to ascii period
                sanitized = re.sub("(…+)", "...", sanitized)  # elipsis doesn't look natural……
                sanitized = re.sub("……", "...", sanitized)  # make double ellipses as one
                sanitized = re.sub("<pc>さん", "<pc>", sanitized)  # don't translate as 3 after player name
                sanitized = re.sub("<cs_pchero>さん", "<cs_pchero>", sanitized)  # don't translate as 3 after player name
                sanitized = re.sub("<kyodai>さん", "<kyodai>", sanitized)  # don't translate as 3 after player name
                sanitized = re.sub("<pc>さま", "<pc>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<cs_pchero>さま", "<cs_pchero>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<kyodai>さま", "<kyodai>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<pc>君", "<pc>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<cs_pchero>君", "<cs_pchero>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<kyodai>君", "<kyodai>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<pc>どの", "<pc>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<cs_pchero>どの", "<cs_pchero>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<kyodai>どの", "<kyodai>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<pc>ちゃん", "<pc>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<cs_pchero>ちゃん", "<cs_pchero>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<kyodai>ちゃん", "<kyodai>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<pc>くん", "<pc>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<cs_pchero>くん", "<cs_pchero>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<kyodai>くん", "<kyodai>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<pc>様", "<pc>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<cs_pchero>様", "<cs_pchero>", sanitized)  # fix poor deepl translation
                sanitized = re.sub("<kyodai>様", "<kyodai>", sanitized)  # fix poor deepl translation
                sanitized = re.sub(
                    "\|", " ", sanitized
                )  # we need these, but they mess up the translation. put them back later
                translation = translate(translation_service, is_pro, sanitized, api_key, region_code)
                # translation = sanitized
                # post process after translation
                translation = translation.strip()
                translation = re.sub(
                    "   ", " ", translation
                )  # translation sometimes comes back with a strange number of spaces
                translation = re.sub("  ", " ", translation)
                translation = textwrap.fill(translation, width=44, replace_whitespace=False)

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
                # lists don't have punctuation, but we need to split them up so we can translate and separate each line item
                split_list = re.split("(\|)", item)
                split_list = [i for i in split_list if i not in [""]]  # remove blank items from list
                for entry in split_list:
                    if entry == "|":  # preserve the pipes, which are used to break the lines up for clarity
                        final_string += entry
                    else:
                        # pre process before translation
                        sanitized = re.sub("\u3000", " ", entry)  # replace full width spaces with ascii spaces
                        sanitized = re.sub(
                            "「", "", sanitized
                        )  # these create a single double quote, which look weird in english
                        sanitized = re.sub("(…+)", "...", sanitized)  # elipsis doesn't look natural with english

                        # post process after translation
                        translation = translate(translation_service, is_pro, sanitized, api_key, region_code)
                        translation = re.sub("\.", "", translation)  # options don't need to end with a period
                        # translation = sanitized
                        final_string += translation

            # this cleans up any blank newlines
            final_string = "\n".join([ll.rstrip() for ll in final_string.splitlines() if ll.strip()])

            # if the string starts with a <select*>, the above will add a pipe at the beginning of the string.
            # make sure the final string doesn't contain this.
            if final_string.startswith("|"):
                final_string = final_string[1:]
            final_string = final_string.replace("\n", "|")

            # make sure there is a space between the player's name and the next word
            # and replace the placeholder tags inserted earlier with the proper tags
            final_string = re.sub("Placeholderpcname", " <pc> ", final_string)
            final_string = re.sub("Placeholdercsname", " <cs_pchero> ", final_string)
            final_string = re.sub("Placeholderkyname", " <kyodai> ", final_string)
            final_string = re.sub("Placeholderpcnam", " <pc> ", final_string)
            final_string = re.sub("Placeholdercsnam", " <cs_pchero> ", final_string)
            final_string = re.sub("Placeholderkynam", " <kyodai> ", final_string)
            final_string = re.sub("Placeholderpcna", " <pc> ", final_string)
            final_string = re.sub("Placeholdercsna", " <cs_pchero> ", final_string)
            final_string = re.sub("Placeholderkyna", " <kyodai> ", final_string)
            final_string = re.sub("Placeholderpcn", " <pc> ", final_string)
            final_string = re.sub("Placeholdercsn", " <cs_pchero> ", final_string)
            final_string = re.sub("Placeholderkyn", " <kyodai> ", final_string)
            final_string = re.sub("placeholderpcname", " <pc> ", final_string)
            final_string = re.sub("placeholdercsname", " <cs_pchero> ", final_string)
            final_string = re.sub("placeholderkyname", " <kyodai> ", final_string)
            final_string = re.sub("placeholderpcnam", " <pc> ", final_string)
            final_string = re.sub("placeholdercsnam", " <cs_pchero> ", final_string)
            final_string = re.sub("placeholderkynam", " <kyodai> ", final_string)
            final_string = re.sub("placeholderpcna", " <pc> ", final_string)
            final_string = re.sub("placeholdercsna", " <cs_pchero> ", final_string)
            final_string = re.sub("placeholderkyna", " <kyodai> ", final_string)
            final_string = re.sub("placeholderpcn", " <pc> ", final_string)
            final_string = re.sub("placeholdercsn", " <cs_pchero> ", final_string)
            final_string = re.sub("placeholderkyn", " <kyodai> ", final_string)
            # make sure end of string doesn't end with line break
            final_string = re.sub("\|<br>$", "", final_string)

    return final_string


def check_deepl_remaining_char_count(key, is_pro):
    if is_pro == "True":
        url = "https://api.deepl.com/v2"
    else:
        url = "https://api-free.deepl.com/v2"
    url += "/usage?auth_key=" + key
    response = requests.get(url)
    return response.text


def read_json_file(base_filename, region_code):
    with open(f"json/_lang/{region_code}/{base_filename}.json", "r+", encoding="utf-8") as json_data:
        return json.loads(json_data.read())


def utf8_len(a_string):
    return len(a_string.encode("utf-8"))


service = "deepl"
pro = False
api_key = "FILL ME IN"
region_code = "en"

file_list = [
    "adhoc_cs_ver23_24_granzedora_finale",
    "adhoc_cs_ver23_ethene_isshou",
    "adhoc_cs_ver23_ethene_lione",
    "adhoc_cs_ver23_ethene_wind_cave",
    "adhoc_cs_ver23_granzedora_lushenda_dragons",
    "adhoc_cs_ver30_dragon_village",
    "adhoc_cs_ver30_dwachakka",
    "adhoc_cs_ver30_eltona",
    "adhoc_cs_ver30_grand_titus",
    "adhoc_cs_ver30_megistris",
    "adhoc_cs_ver30_ogreed",
    "adhoc_cs_ver30_wena_islands",
]

for the_file in file_list:
    cur_file = the_file
    a_file = open(f"../json/_lang/en/" + cur_file + ".json", "r", encoding="utf-8")
    data = json.load(a_file)
    file_length = len(data)
    a_file.close()

    with alive_bar(file_length, title="Translating..", theme="musical", length=20) as bar:
        for item in data:
            bar()
            key, value = list(data[item].items())[0]
            if value == "" and utf8_len(key) > 8:
                deepl_api_key = api_key
                dialog = sanitized_dialog_translate(service, pro, key, deepl_api_key, region_code)
                if utf8_len(dialog) <= utf8_len(key):
                    data[item][key] = dialog
                    with open(f"../json/_lang/en/" + cur_file + ".json", "wb") as fp:
                        fp.write(json.dumps(data, ensure_ascii=False, indent=4, sort_keys=False).encode("utf-8"))
                else:
                    print(f"File: {cur_file}\nDid not translate: {key}")
