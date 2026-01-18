# fmt: off
# ruff: noqa

# devs made a custom implementation of memchr from cpp to search byte arrays.
# think I found this backtracing from ws2_32.recv, but there are several strings
# in the game that only seem visible during network handling; they aren't
# passed through any other type of string templating functions like others are.
# this hits more than we need, but we'll just ignore strings that aren't japanese.
# >> DQXGame.exe+9A19F0 - 8B 44 24 0C           - mov eax,[esp+0C]
# >> DQXGame.exe+9A19F4 - 53                    - push ebx
# >> DQXGame.exe+9A19F5 - 85 C0                 - test eax,eax
# >> DQXGame.exe+9A19F7 - 74 52                 - je DQXGame.exe+9A1A4B
#    DQXGame.exe+9A19F9 - 8B 54 24 08           - mov edx,[esp+08]
#    DQXGame.exe+9A19FD - 33 DB                 - xor ebx,ebx
#    DQXGame.exe+9A19FF - 8A 5C 24 0C           - mov bl,[esp+0C]
#    DQXGame.exe+9A1A03 - F7 C2 03000000        - test edx,00000003
# 8B 44 24 0C 53 85 C0 74 52
mem_chr_trigger = rb"\x8B\x44\x24\x0C\x53\x85\xC0\x74\x52"

#############################################
# "Patterns" seen to find various text.
# Not code signatures, so these will likely
# change and need to be updated on patches.
#############################################

# D8 E5 ?? ?? ?? ?? ?? ?? 68 0C ?? ?? E?
concierge_name_pattern = rb"\xD8\xE5......\x68\x0C..[\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEF]"

# pattern for menu ai to rename. (58 bytes)
# 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? ?? ?? 00 00 00 ?? 1? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? E?
menu_ai_name_pattern = rb"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00...........\x00..\x00\x00.....\x00\x00\x00.[\x1B\x1C].....\x00.....\x00..[\xE3\xEF]"

# pattern for comm_names.
# E? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 0F 00 00 00 01 02 00 00 01 00 00 (32 bytes)
comm_name_pattern = rb"[\xE3\xEF].................\x00\x00\x0F\x00\x00\x00\x01\x02\x00\x00\x01\x00\x00"

# "動画配信の際はサーバー" found in notice box on login. Bytes are just the words encoded into utf-8
# E5 8B 95 E7 94 BB E9 85 8D E4 BF A1 E3 81 AE E9 9A 9B E3 81 AF E3 82 B5 E3 83 BC E3 83 90 E3 83 BC
notice_string = rb"\xE5\x8B\x95\xE7\x94\xBB\xE9\x85\x8D\xE4\xBF\xA1\xE3\x81\xAE\xE9\x9A\x9B\xE3\x81\xAF\xE3\x82\xB5\xE3\x83\xBC\xE3\x83\x90\xE3\x83\xBC"
