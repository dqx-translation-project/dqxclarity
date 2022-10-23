from os import listdir, path, remove, mkdir, makedirs, system
from shutil import rmtree, copy2
from pathlib import Path
import json
import random
from alive_progress import alive_bar
import csv
import sys

sys.path.append("../")
from clarity import query_csv
from common.signatures import text_pattern, index_pattern, foot_pattern
from common.memory import pattern_scan, read_bytes, get_start_of_game_text, find_first_match
from blacklist import indx_blacklist


def write_file(path: str, filename: str, attr: str, data: str):
    """Writes a string to a file."""
    with open(f"{path}/{filename}", attr, encoding="utf-8") as open_file:
        open_file.write(data)


def write_csv(hex_bytes: str, filename: str):
    csv_file = "bms_hex_dict.csv"
    csv = Path(csv_file)
    if not csv.is_file():
        write_file("./", csv_file, "a", "file,hex_string\n")

    write_file("./", csv_file, "a", f"{filename},{hex_bytes}\n")


def split_hex_into_spaces(hex_str: str):
    """
    Breaks a string up by putting spaces between every two characters.
    Used to format a hex string.
    """
    spaced_str = " ".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))
    return spaced_str.upper()


def write_dict(file: str, new_name: str, skip_file_read=False, hex_bytes=""):
    """
    Writes entry in hex_dict file.

    file: Dumped file name to read for INDX
    new_name: What to name the file in hex_dict
    """
    if not skip_file_read:
        with open(f"dqx_out/{file}", "rb") as f:
            the_bytes = f.seek(80)  # INDX starts at 0x80
            the_bytes = f.read(64)  # get unique bytes for hex dict. 64 is arbitrary, but clarity expects it

    # write indx bytes to dict
    if hex_bytes == "":
        str_bytes = the_bytes.hex()
        split_hex = split_hex_into_spaces(str_bytes)
    else:
        split_hex = hex_bytes

    write_csv(split_hex, new_name)


def query_csv(file: str, compare_type="hex") -> bool:
    """
    Accepts an EVT file, queries the header for INDX bytes and checks if entry exists in CSV.
    """
    if compare_type == "hex":
        with open(f"{file}", "rb") as f:
            the_bytes = f.seek(80)  # INDX starts at 0x80
            the_bytes = f.read(64)  # get unique bytes for hex dict. 64 is arbitrary
        with open("bms_hex_dict.csv") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row["hex_string"] == split_hex_into_spaces(the_bytes.hex()):
                    return True
    elif compare_type == "filename":
        with open("bms_hex_dict.csv") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["file"] == f"json\_lang\en\{file}":
                    return True


def check_blacklist(file: str):
    """
    blacklist.py houses all of the files that we don't care about.
    If a file has a matching INDX entry, return True.
    """
    with open(f"{file}", "rb") as f:
        the_bytes = f.seek(80)  # INDX starts at 0x80
        the_bytes = f.read(64)  # get unique bytes for hex dict. 64 is arbitrary
        hex_string = str(the_bytes.hex(' '))
        hex_upper = hex_string.upper()

    if hex_upper in indx_blacklist:
        return True


def __find_start_of_text(file: str) -> int:
    with open(f"dqx_out/{file}", "rb") as f:
        s = f.read()
    start_position = s.find(text_pattern)
    if start_position:
        return int(start_position)


def __find_start_of_game_text(file: str) -> int:
    position = __find_start_of_text(file)
    with open(f"dqx_out/{file}", "rb") as f:
        start = f.seek(position + 14)  # jump passed junk bytes
        start = f.read(1)
        while start:
            start = f.read(1)
            if start != b"\x00":
                return int(f.tell() - 1)


def __find_end_of_game_text(file: str, position: int) -> int:
    with open(f"dqx_out/{file}", "rb") as f:
        s = f.read()
    end_position = s.find(foot_pattern, position)
    if end_position:  # we reached eof, but have junk bytes
        return int(end_position)


def get_text_range(file: str) -> tuple:
    text_start = __find_start_of_game_text(file)
    text_end = __find_end_of_game_text(file, text_start)
    return (text_start, text_end)


def format_to_json(json_data, data, lang, number):
    """Accepts data that is used to return a nested json."""
    json_data[number] = {}
    if data == "":
        json_data[number][f"clarity_nt_char_{number}"] = f"clarity_nt_char_{number}"
    elif data == "　":
        json_data[number][f"clarity_ms_space_{number}"] = f"clarity_ms_space_{number}"
    else:
        if lang == "ja":
            json_data[number][data] = data
        else:
            json_data[number][data] = ""

    return json_data


def clean_workspace():
    if path.exists("bms_hex_dict.csv"):
        remove("bms_hex_dict.csv")

    if path.exists("hex_dict.csv"):
        remove("hex_dict.csv")

    if path.exists("json_out"):
        rmtree("json_out")
    makedirs("json_out/en")
    makedirs("json_out/ja")

    if path.exists("json"):
        rmtree("json")
    makedirs("json/_lang/en")
    makedirs("json/_lang/ja")

    hyde_folders = ["src", "dst", "out"]
    for folder in hyde_folders:
        if path.exists(f"hyde_json_merge/{folder}"):
            rmtree(f"hyde_json_merge/{folder}")
        mkdir(f"hyde_json_merge/{folder}")


def sanitize_bytes(data: str) -> str:
    out_data = data.replace("\x0a", "\x7c")
    out_data = out_data.replace("\x00", "\x0a")
    out_data = out_data.replace("\x09", "\x5c\x74")

    return out_data


def read_json_file(file):
    with open(file, "r", encoding="utf-8") as json_data:
        return json.loads(json_data.read())


def compare_jsons(source: str):
    """
    Compare the top few entries of a json file with another and look for a match.
    Returns either the name of the file we already have or nothing if no match.

    source: Diff file dumped by bms
    """
    orig = read_json_file(f"json_out/en/{source}")
    orig_list = []
    count = 0
    # grab first 20 entries from file we already have
    for item in orig:
        count += 1
        key, value = list(orig[item].items())[0]
        orig_list.append(key)
        if count == 20:
            break
    # match the previous 20 entries against every json file until we find a match
    for file in listdir("../../json/_lang/en"):
        new = read_json_file(f"../../json/_lang/en/{file}")
        list_len = len(orig_list)
        count = 0
        for item in new:
            key, value = list(new[item].items())[0]
            if list_len == count:
                return file
            elif key == orig_list[count] and list_len > count:  # some files don't have 20 entries
                count += 1
                if list_len == count:
                    return file
            else:
                break


def __format_to_json(json_data, data, lang, number):
    """Accepts data that is used to return a nested json."""
    json_data[number] = {}
    if data == "":
        json_data[number][f"clarity_nt_char_{number}"] = f"clarity_nt_char_{number}"
    elif data == "　":
        json_data[number][f"clarity_ms_space_{number}"] = f"clarity_ms_space_{number}"
    else:
        if lang == "ja":
            json_data[number][data] = data
        else:
            json_data[number][data] = ""

    return json_data


def dump_all_game_files():
    """
    Searches for all INDX entries in memory and dumps
    the entire region, then converts said region to nested json.
    """
    game_file_addresses = pattern_scan(pattern=index_pattern, return_multiple=True)

    with alive_bar(len(game_file_addresses), title="Dumping from memory..", theme="smooth", length=20) as bar:
        for address in game_file_addresses:
            bar()
            hex_result = split_hex_into_spaces(str(read_bytes(address, 64).hex()))
            start_addr = get_start_of_game_text(address)  # make sure we start on the first byte of the first letter
            if start_addr is not None:
                end_addr = find_first_match(start_addr, foot_pattern)
                if end_addr is not None:
                    bytes_to_read = end_addr - start_addr
                    if bytes_to_read < 0:
                        continue
                    game_data = read_bytes(start_addr, bytes_to_read).rstrip(b"\x00").hex()
                    if len(game_data) % 2 != 0:
                        game_data = game_data + "0"

                    try:
                        game_data = bytes.fromhex(game_data).decode("utf-8")
                    except UnicodeDecodeError:
                        continue  # incomplete files are sometimes loaded. ignore them
                    game_data = game_data.replace("\x0a", "\x7c")
                    game_data = game_data.replace("\x00", "\x0a")
                    game_data = game_data.replace("\x09", "\x5c\x74")

                    jsondata_ja = {}
                    jsondata_en = {}
                    number = 1

                    for line in game_data.split("\n"):
                        json_data_ja = __format_to_json(jsondata_ja, line, "ja", number)
                        json_data_en = __format_to_json(jsondata_en, line, "en", number)
                        number += 1

                    json_data_ja = json.dumps(jsondata_ja, indent=2, sort_keys=False, ensure_ascii=False)

                    json_data_en = json.dumps(jsondata_en, indent=2, sort_keys=False, ensure_ascii=False)

                    file = "clarity_" + str((random.randint(1, 1000000000))) + ".json"
                    json_path_ja = "json_out/ja"
                    json_path_en = "json_out/en"

                    write_file(json_path_ja, file, "w+", json_data_ja)
                    write_file(json_path_en, file, "w+", json_data_en)

                    matching_file = compare_jsons(file)

                    # stage files for migration
                    if matching_file:
                        copy2(f"json_out/en/{file}", f"hyde_json_merge/dst/{matching_file}")  # stage new file for port
                        copy2(f"json_out/ja/{file}", f"json/_lang/ja/{matching_file}")  # move new ja to new folder
                        copy2(f"../../json/_lang/en/{matching_file}", "hyde_json_merge/src")  # stage orig file for port
                        write_dict(
                            f"json\_lang\en\{file}",
                            f"json\_lang\en\{matching_file}",
                            skip_file_read=True,
                            hex_bytes=hex_result,
                        )
                    else:
                        print(
                            f"No match found for {file}."
                        )  # nothing to port b/c new file. if file not in blacklist, move new files and do nothing
                        if hex_result in indx_blacklist:
                            continue
                        else:
                            copy2(f"json_out/en/{file}", f"json/_lang/en")  # move new en to new folder
                            copy2(f"json_out/ja/{file}", f"json/_lang/ja")  # move new ja to new folder
                            write_dict(
                                f"json\_lang\en\{file}", f"json\_lang\en\{file}", skip_file_read=True, hex_bytes=hex_result
                            )


def sort_csv():
    """
    Ensures only unique lines are present and sorts them, then writes to a final hex_dict.csv file.
    """
    lines_seen = set()
    outfile = open("hex_dict.csv", "w")
    for line in open("bms_hex_dict.csv", "r"):
        if line not in lines_seen:  # not a duplicate
            lines_seen.add(line)
    outfile.writelines(sorted(lines_seen))
    outfile.close()


def end_with_newline():
    for file in listdir("json/_lang/en"):
        with open(f"json/_lang/en/{file}", "r", encoding="utf-8") as f:
            last_en = f.readlines()[-1]
        if last_en == "}":
            with open(f"json/_lang/en/{file}", "a", encoding="utf-8") as f:
                f.write("\n")


if __name__ == "__main__":
    clean_workspace()

    # dump files from memory and place in folders to process
    # DQX needs to be open for this step
    dump_all_game_files()

    dir_count = len(listdir("dqx_out"))

    with alive_bar(dir_count, title="Analyzing EVTs..", theme="smooth", length=20) as bar:
        for file in listdir("dqx_out"):
            bar()
            if query_csv(f"dqx_out/{file}"):  # if we dumped it from memory already, don't do double work
                continue

            if check_blacklist(f"dqx_out/{file}"):
                continue

            bounds = get_text_range(file)
            num_to_read = bounds[1] - bounds[0]  # read in data we care about

            with open(f"dqx_out/{file}", "rb") as f:
                s = f.seek(bounds[0])
                s = f.read(num_to_read)

            game_data = s.rstrip(b"\x00")
            game_data = game_data.hex()

            game_data = bytes.fromhex(game_data).decode("utf-8")

            # sanitize hex for weblate
            game_data = sanitize_bytes(game_data)

            jsondata_ja = {}
            jsondata_en = {}
            number = 1

            # create json string
            for line in game_data.split("\n"):
                json_data_ja = format_to_json(jsondata_ja, line, "ja", number)
                json_data_en = format_to_json(jsondata_en, line, "en", number)
                number += 1

            # format to actual json
            json_data_ja = json.dumps(jsondata_ja, indent=2, sort_keys=False, ensure_ascii=False)
            json_data_en = json.dumps(jsondata_en, indent=2, sort_keys=False, ensure_ascii=False)

            # write en and ja json to file
            json_file = path.splitext(file)[0] + ".json"
            json_path_ja = "json_out/ja"
            json_path_en = "json_out/en"

            Path(json_path_ja).mkdir(parents=True, exist_ok=True)
            Path(json_path_en).mkdir(parents=True, exist_ok=True)

            write_file(json_path_ja, json_file, "w+", json_data_ja)
            write_file(json_path_en, json_file, "w+", json_data_en)

            matching_file = compare_jsons(json_file)

            # stage files for migration
            if matching_file:
                # we found a match, but we want to make double sure we haven't seen this file as
                # compare_jsons is not perfect. check the csv to make sure no match. if match, this file
                # is a dupe and we ignore it.
                check_csv = query_csv(matching_file, compare_type="filename")
                if check_csv:
                    continue
                copy2(f"json_out/en/{json_file}", f"hyde_json_merge/dst/{matching_file}")  # stage new file for port
                copy2(f"json_out/ja/{json_file}", f"json/_lang/ja/{matching_file}")  # move new ja to new folder
                copy2(f"../../json/_lang/en/{matching_file}", "hyde_json_merge/src")  # stage orig file for port
                write_dict(f"{file}", f"json\_lang\en\{matching_file}")
            else:
                # nothing to port b/c new file. move new files and do nothing
                copy2(f"json_out/en/{json_file}", f"json/_lang/en")  # move new en to new folder
                copy2(f"json_out/ja/{json_file}", f"json/_lang/ja")  # move new ja to new folder
                write_dict(f"{file}", f"json\_lang\en\{json_file}")

    # run hyde's json migration and move files dumped in out to new folder. this is now our new json batch
    exe = "hyde_json_merge\json-conv.exe"

    for filename in listdir("hyde_json_merge/src"):
        system(
            f"{exe} -s hyde_json_merge/src/{filename} -d hyde_json_merge/dst/{filename} -o hyde_json_merge/out/{filename}"
        )
        copy2(f"hyde_json_merge/out/{filename}", "json/_lang/en")

    # we need to go back and check our existing hex dict. not all files in memory or these dumps will
    # be accounted for and were dumped as they were encountered in game. query the current hex_dict
    # and port those values over.
    with open("../hex_dict.csv", "r") as source, open("bms_hex_dict.csv", "r") as dest:
        source_file = source.readlines()
        dest_file = dest.readlines()

    # make a new list with only filenames
    new_dest_file = []
    for line in dest_file:
        new_dest_file.append(line.split(",")[0])

    # query our existing csv. if an entry in here isn't in the new one, add it. also, move the file over to json/_lang
    for line in source_file:
        filename = line.split(",")[0]
        hex_value = line.split(",")[1].rstrip()
        if filename not in new_dest_file:
            write_dict(filename, filename, skip_file_read=True, hex_bytes=hex_value)
            ja_filename = filename.replace("\en", "\ja")
            copy2(f"../../{filename}", "json/_lang/en")  # copy en to new folder
            copy2(f"../../{ja_filename}", "json/_lang/ja")

    # ensure our new csv is sorted and has unique records
    sort_csv()

    # make sure each json ends with a newline
    end_with_newline()
    
    # clean up space, but leave json folder and new hex_dict.csv
    rmtree("json_out")
    rmtree("dqx_out")
    remove("bms_hex_dict.csv")
