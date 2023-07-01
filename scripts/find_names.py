import argparse
import sys
import pymem


# zone into megistris and stand at the entrance
megistris_npc_names = [
    "ハパリーパ",
    "魚交換員ノポナ",
    "紹介人プリュノ",
    "チャヌジャ",
    "神官ペオ",
]

# zone out of megistris and don't move
megistris_monster_names = [
    "おむつっこり",
    "リザードマン",
]

# add your party members here
party_npc_names = [
    "ももちゃん",
    "べっぴん",
    "ミルラ",
]


DQX = pymem.Pymem("DQXGame.exe")


def get_npc_results():
    npcs_found = []
    for npc in megistris_npc_names:
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


def get_monster_results():
    monsters_found = []
    for monster in megistris_monster_names:
        pattern = monster.encode(encoding="utf-8")
        results = DQX.pattern_scan_all(pattern=pattern, return_multiple=True)
        for result in results:
            data = DQX.read_bytes(result - 48, 49)

            # correct pattern never starts with this
            if data.startswith(b"\x00\x00\x00\x00"):
                continue
            # correct pattern always has nulls in these positions
            if data[4:9] != b"\x00\x00\x00\x00\x00":
                continue

            monsters_found.append(data.hex(" ", 1).upper())
    return monsters_found


def get_party_member_results():
    players_found = []
    for player in party_npc_names:
        pattern = player.encode(encoding="utf-8")
        results = DQX.pattern_scan_all(pattern=pattern, return_multiple=True)
        for result in results:
            data = DQX.read_bytes(result - 48, 49)

            # correct pattern never starts with this
            if data.startswith(b"\x00\x00\x00\x00"):
                continue
            # correct pattern always has nulls in these positions
            if data[4:9] != b"\x00\x00\x00\x00\x00":
                continue

            players_found.append(data.hex(" ", 1).upper())
    return players_found


def write_to_file(data: str):
    with open("npc_monster_pattern.log", "a+") as f:
        f.write(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Returns bytes following an NPC's name for pattern scanning.")
    parser.add_argument("-n", default=False, action="store_true", help="Scans for configured NPCs and writes results to file.")
    parser.add_argument("-m", default=False, action="store_true", help="Scans for configured monsters and writes results to file.")
    parser.add_argument("-p", default=False, action="store_true", help="Scans for configured party members and writes results to file.")
    args = parser.parse_args(args=None if sys.argv[1:] else ["--help"])

    if args.n:
        results = get_npc_results()
        if results:
            write_to_file("NPCs:\n")
            for result in results:
                write_to_file(f"{result}\n")
            write_to_file("\n")
    if args.m:
        results = get_monster_results()
        if results:
            write_to_file("Monsters:\n")
            for result in results:
                write_to_file(f"{result}\n")
            write_to_file("\n")
    if args.p:
        results = get_party_member_results()
        if results:
            write_to_file("Party members:\n")
            for result in results:
                write_to_file(f"{result}\n")
            write_to_file("\n")  
