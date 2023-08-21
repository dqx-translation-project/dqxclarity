import argparse
import pymem
import sys

# zone into megistris and stand at the entrance
npc_names = [
    "ハパリーパ",
    "魚交換員ノポナ",
    "紹介人プリュノ",
    "チャヌジャ",
    "神官ペオ",
]

# zone outside of megistris and don't move
monster_names = [
    "おむつっこり",
    "リザードマン",
]

# add your party members here
party_names = [
    "ももちゃん",
    "べっぴん",
    "ミルラ",
]


DQX = pymem.Pymem("DQXGame.exe")


def get_scan_results(names: list):
    npcs_found = []
    for npc in names:
        pattern = npc.encode(encoding="utf-8")
        results = DQX.pattern_scan_all(pattern=pattern, return_multiple=True)
        for result in results:
            data = DQX.read_bytes(result - 48, 49)

            # correct pattern never starts with this
            if data.startswith(b"\x00\x00\x00\x00"):
                continue
            # correct pattern always has nulls in these positions
            if data[4:9] != b"\x00\x00\x00\x00\x00":
                continue

            npcs_found.append(data.hex(" ", 1).upper())
    return npcs_found


def write_to_file(data: str):
    with open("npc_monster_pattern.log", "a+") as f:
        f.write(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Returns bytes following an NPC's name for pattern scanning. Used specifically to target the 'npc_monster_pattern' pattern.")
    parser.add_argument("-n", "--npcs", default=False, action="store_true", help="Scans for configured NPCs and writes results to file.")
    parser.add_argument("-m", "--monsters", default=False, action="store_true", help="Scans for configured monsters and writes results to file.")
    parser.add_argument("-p", "--party", default=False, action="store_true", help="Scans for configured party members and writes results to file.")
    args = parser.parse_args(args=None if sys.argv[1:] else ["--help"])

    if args.npcs:
        results = get_scan_results(npc_names)
        if results:
            write_to_file("NPCs:\n---------------------\n")
            for result in results:
                write_to_file(f"{result}\n")
            write_to_file("\n")
    if args.monsters:
        results = get_scan_results(monster_names)
        if results:
            write_to_file("Monsters:\n---------------------\n")
            for result in results:
                write_to_file(f"{result}\n")
            write_to_file("\n")
    if args.party:
        results = get_scan_results(party_names)
        if results:
            write_to_file("Party members:\n---------------------\n")
            for result in results:
                write_to_file(f"{result}\n")
            write_to_file("\n")
