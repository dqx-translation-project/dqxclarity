#############################################
# DQX functions that shouldn't change much
# as these are code signatures.
#############################################

# takes you to the section of the function where you can read where dialog is stored before
# it's rendered to screen. captures npc text.
# FF ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? FD FF FF FF E8
#    DQXGame.exe+4F7F6F - 8D 4D C8              - lea ecx,[ebp-38]
#    DQXGame.exe+4F7F72 - 56                    - push esi
#    DQXGame.exe+4F7F73 - E8 186CCAFF           - call DQXGame.exe+19EB90
#    DQXGame.exe+4F7F78 - 8D 4D C8              - lea ecx,[ebp-38]
#    DQXGame.exe+4F7F7B - E8 107ACAFF           - call DQXGame.exe+19F990
# >> DQXGame.exe+4F7F80 - FF 73 08              - push [ebx+08]
# >> DQXGame.exe+4F7F83 - C7 45 F4 00000000     - mov [ebp-0C],00000000
# >> DQXGame.exe+4F7F8A - C7 45 FC FDFFFFFF     - mov [ebp-04],FFFFFFFD
# >> DQXGame.exe+4F7F91 - E8 8A22C4FF           - call DQXGame.exe+13A220
#    DQXGame.exe+4F7F96 - 8B 15 C8C89302        - mov edx,[DQXGame.exe+1C2C8C8]
#    DQXGame.exe+4F7F9C - 83 C4 04              - add esp,04
#    DQXGame.exe+4F7F9F - 8B F8                 - mov edi,eax
dialog_trigger = rb"\xFF..\xC7\x45.\x00\x00\x00\x00\xC7\x45.\xFD\xFF\xFF\xFF\xE8"

# function that is triggered when a quest window opens. used for translating quest text
# 8D 8E 78 04 00 00 E8 ?? ?? ?? ?? 5F
#    DQXGame.exe.text+680E0A - 74 35                 - je DQXGame.exe.text+680E41
#    DQXGame.exe.text+680E0C - 83 C0 14              - add eax,14
#    DQXGame.exe.text+680E0F - 74 30                 - je DQXGame.exe.text+680E41
#    DQXGame.exe.text+680E11 - 50                    - push eax
# >> DQXGame.exe.text+680E12 - 8D 8E 78040000        - lea ecx,[esi+00000478]
#    DQXGame.exe.text+680E18 - E8 A38CB0FF           - call DQXGame.exe.text+189AC0
#    DQXGame.exe.text+680E1D - 5F                    - pop edi
#    DQXGame.exe.text+680E1E - C6 86 D0070000 01     - mov byte ptr [esi+000007D0],01
#    DQXGame.exe.text+680E25 - B0 01                 - mov al,01
#    DQXGame.exe.text+680E27 - C7 46 50 00000000     - mov [esi+50],00000000
#    DQXGame.exe.text+680E2E - C7 46 4C 01000000     - mov [esi+4C],00000001
#    DQXGame.exe.text+680E35 - C7 46 54 00000000     - mov [esi+54],00000000
#    DQXGame.exe.text+680E3C - 5E                    - pop esi
#    DQXGame.exe.text+680E3D - 5D                    - pop ebp
#    DQXGame.exe.text+680E3E - C2 0400               - ret 0004
quest_text_trigger = rb"\x8D\x8E\x78\x04\x00\x00\xE8....\x5F"

# Integrity check + hooking addresses
# 8D 64 24 FC 89 14 24 89 4C 24 FC 8D 64 24 FC 89 44 24 FC 8d 64 24 FC E9 ?? ?? ?? ?? 8D 64 24 FC 89 34 24
#    DQXGame.exe+7EFBD54 - 8D 64 24 04           - lea esp,[esp+04]
#    DQXGame.exe+7EFBD58 - FF 64 24 FC           - jmp dword ptr [esp-04]
# >> DQXGame.exe+7EFBD5C - 8D 64 24 FC           - lea esp,[esp-04]
#    DQXGame.exe+7EFBD60 - 89 14 24              - mov [esp],edx
#    DQXGame.exe+7EFBD63 - 89 4C 24 FC           - mov [esp-04],ecx
#    DQXGame.exe+7EFBD67 - 8D 64 24 FC           - lea esp,[esp-04]
#    DQXGame.exe+7EFBD6B - 89 44 24 FC           - mov [esp-04],eax
#    DQXGame.exe+7EFBD6F - 8D 64 24 FC           - lea esp,[esp-04]
#    DQXGame.exe+7EFBD73 - E9 33BB26F8           - jmp DQXGame.exe+1678AB
#    DQXGame.exe+7EFBD78 - 8D 64 24 FC           - lea esp,[esp-04]
#    DQXGame.exe+7EFBD7C - 89 34 24              - mov [esp],esi
#    DQXGame.exe+7EFBD7F - 8D 85 B8FCFFFF        - lea eax,[ebp-00000348]
#    DQXGame.exe+7EFBD85 - 57                    - push edi
integrity_check = rb"\x8D\x64\x24\xFC\x89\x14\x24\x89\x4C\x24\xFC\x8D\x64\x24\xFC\x89\x44\x24\xFC\x8d\x64\x24\xFC\xE9....\x8D\x64\x24\xFC\x89\x34\x24"

# a lot of network text that is drawn to the screen comes through this function
# 51 51 8B C4 89 10 8B CF
#    DQXGame.exe+4F3E3D - 8B CA                 - mov ecx,edx
#    DQXGame.exe+4F3E3F - 8D 71 01              - lea esi,[ecx+01]
#    DQXGame.exe+4F3E42 - 8A 01                 - mov al,[ecx]
#    DQXGame.exe+4F3E44 - 41                    - inc ecx
#    DQXGame.exe+4F3E45 - 84 C0                 - test al,al
#    DQXGame.exe+4F3E47 - 75 F9                 - jne DQXGame.exe+4F3E42
#    DQXGame.exe+4F3E49 - 2B CE                 - sub ecx,esi
# >> DQXGame.exe+4F3E4B - 51                    - push ecx
# >> DQXGame.exe+4F3E4C - 51                    - push ecx
# >> DQXGame.exe+4F3E4D - 8B C4                 - mov eax,esp
# >> DQXGame.exe+4F3E4F - 89 10                 - mov [eax],edx
# >> DQXGame.exe+4F3E51 - 8B CF                 - mov ecx,edi
#    DQXGame.exe+4F3E53 - E8 B8D0CAFF           - call DQXGame.exe+1A0F10
#    DQXGame.exe+4F3E58 - 8A D8                 - mov bl,al
#    DQXGame.exe+4F3E5A - 8B 47 0C              - mov eax,[edi+0C]
#    DQXGame.exe+4F3E5D - B9 0C000000           - mov ecx,0000000C
network_text_trigger = rb"\x51\x51\x8B\xC4\x89\x10\x8B\xCF"

# player and sibling names on login. use this to figure out what the player is logged in as
# 55 8B EC 56 8B F1 57 8B 46 58 85 C0
# DQXGame.exe+422C70 - 55                    - push ebp
# DQXGame.exe+422C71 - 8B EC                 - mov ebp,esp
# DQXGame.exe+422C73 - 56                    - push esi
# DQXGame.exe+422C74 - 8B F1                 - mov esi,ecx
# DQXGame.exe+422C76 - 57                    - push edi
# DQXGame.exe+422C77 - 8B 46 58              - mov eax,[esi+58]
# DQXGame.exe+422C7A - 85 C0                 - test eax,eax
# DQXGame.exe+422C7C - 74 10                 - je DQXGame.exe+422C8E
# DQXGame.exe+422C7E - 50                    - push eax
# DQXGame.exe+422C7F - E8 9CAEC1FF           - call DQXGame.exe+3DB20
# DQXGame.exe+422C84 - 83 C4 04              - add esp,04
# DQXGame.exe+422C87 - C7 46 58 00000000     - mov [esi+58],00000000
# DQXGame.exe+422C8E - 6A 02                 - push 02
# DQXGame.exe+422C90 - 68 B0000000           - push 000000B0
# DQXGame.exe+422C95 - E8 F6ADC1FF           - call DQXGame.exe+3DA90
player_sibling_name_trigger = rb"\x55\x8B\xEC\x56\x8B\xF1\x57\x8B\x46\x58\x85\xC0"

# top-right corner text from NPCs. seen primarily in v5/v6.
# how it was found:
# - Quest 764 has a way to test reproducing text in the top right
# - Search for the text she says while it's up
#   - All strings she might say during the quest are loaded into memory
# - Put a "Find what writes here" on several of the results returned
# - While in the loom portion of the quest, mash any button to fail the
#   step and get her to say something new. Hope you picked an address
#   that has a temporary string in it and was overwritten with the new
#   string.
#
#    DQXGame.exe+6B2130 - 55                    - push ebp
#    DQXGame.exe+6B2131 - 8B EC                 - mov ebp,esp
#    DQXGame.exe+6B2133 - 8B 45 08              - mov eax,[ebp+08]
#    DQXGame.exe+6B2136 - 83 EC 14              - sub esp,14
#    DQXGame.exe+6B2139 - 53                    - push ebx
#    DQXGame.exe+6B213A - 56                    - push esi
#    DQXGame.exe+6B213B - 8B F1                 - mov esi,ecx
#    DQXGame.exe+6B213D - 57                    - push edi
#    DQXGame.exe+6B213E - 8B 7D 0C              - mov edi,[ebp+0C]
#    DQXGame.exe+6B2141 - 85 C0                 - test eax,eax
#    DQXGame.exe+6B2143 - 0F84 96010000         - je DQXGame.exe+6B22DF
# >> DQXGame.exe+6B2149 - 8B D0                 - mov edx,eax
# >> DQXGame.exe+6B214B - 8D 5A 01              - lea ebx,[edx+01]
# >> DQXGame.exe+6B214E - 66 90                 - nop 2
# >> DQXGame.exe+6B2150 - 8A 0A                 - mov cl,[edx]
# >> DQXGame.exe+6B2152 - 42                    - inc edx
# >> DQXGame.exe+6B2153 - 84 C9                 - test cl,cl
# >> DQXGame.exe+6B2155 - 75 F9                 - jne DQXGame.exe+6B2150
# >> DQXGame.exe+6B2157 - 2B D3                 - sub edx,ebx
# >> DQXGame.exe+6B2159 - 0F84 80010000         - je DQXGame.exe+6B22DF
#    DQXGame.exe+6B215F - 51                    - push ecx
#    DQXGame.exe+6B2160 - 8B CC                 - mov ecx,esp
#    DQXGame.exe+6B2162 - 89 01                 - mov [ecx],eax
#    DQXGame.exe+6B2164 - 8D 45 F0              - lea eax,[ebp-10]
#    DQXGame.exe+6B2167 - 50                    - push eax
#    DQXGame.exe+6B2168 - 8B CE                 - mov ecx,esi
# 8B D0 8D 5A 01 66 90 8A 0A 42 84 C9 75 F9 2B D3 0F
corner_text_trigger = rb"\x8B\xD0\x8D\x5A\x01\x66\x90\x8A\x0A\x42\x84\xC9\x75\xF9\x2B\xD3\x0F"

#############################################
# "Patterns" seen to find various text.
# Not code signatures, so these will likely
# change and need to be updated on patches.
#############################################

# pattern for npc/monsters to rename. (49 bytes)
# covers:
#   - NPC nameplates
#   - Monster nameplates
#   - Monter name references when inspecting
#   - Monster names appearing in the battle menu
#   - Party nameplates (don't confuse with party names on the right side of the screen)
#       - Does not do the player's nameplate

# npc:     8C 75 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 B0 3C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E?
# monster: 8C 75 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 10 29 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E?
# party:   8C 75 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 98 2B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E?
npc_monster_pattern = rb"\x8C\x75..\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00....\x00.......\x00\x00\x00\x00.\x00\x00\x00[\xB0\x10\x98][\x3C\x29\x2B]..........[\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEF]"

# pattern for concierge names (13 bytes)
# C8 21 ?? ?? ?? ?? ?? ?? 04 22 ?? ?? E?
concierge_name_pattern = rb"\xC8\x21......\x04\x22..[\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEF]"

# pattern for player names to rename. (49 bytes)
# 8C 75 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 B0 8A ?? 0? ?? ?? ?? ?? ?? ?? ?? 0? E?
player_name_pattern = rb"\x8C\x75..\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00....\x00...\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xB0\x8A.[\x01\x02].......[\x01\x02][\xE3\xEF]"
# pattern for sibling names to rename. (52 bytes) (can't find a reliable one right now, will need to test more.)
# 0? ?? 00 ?? 00 00 00 ?? ?? 00 02 ?? 00 ?? 00 ?? 00 00 00 00 00 ?? 00 ?? ?? 00 00 ?? ?? ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? ?? 00 00 00 00 ?? ?? 00 00 00 00 E?
sibling_name_pattern = rb"[\x01\x02].\x00.\x00\x00\x00..\x00\x02.\x00.\x00.\x00\x00\x00\x00\x00.\x00..\x00\x00...\x00.\x00...\x00.\x00..\x00\x00\x00\x00..\x00\x00\x00\x00[\xE3\xEF]"

# pattern for menu ai to rename. (58 bytes)
# 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? ?? ?? 00 00 00 ?? 1? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? E?
menu_ai_name_pattern = rb"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00...........\x00..\x00\x00.....\x00\x00\x00.[\x1B\x1C].....\x00.....\x00..[\xE3\xEF]"

# pattern for comm_names.
# E? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 0F 00 00 00 01 02 00 00 01 00 00 (32 bytes)
comm_name_pattern_1 = rb"[\xE3\xEF].................\x00\x00\x0F\x00\x00\x00\x01\x02\x00\x00\x01\x00\x00"
# 09 E? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4? 38 00 00 00
comm_name_pattern_2 = rb"\x09[\xE3\xEF].................\x00.................\x38\x00\x00\x00"

# Main walkthrough text that loads on login. I can't figure out what function loads this on login,
# so scanning for this for now. AC is also preventing this from just being accessible via hooks. (17 bytes)
# 04 02 ?? ?? 10 00 00 00 C0 ?? ?? ?? 00 00 00 00 E?
walkthrough_pattern = rb"\x04\x02..\x10\x00\x00\x00\xC0...\x00\x00\x00\x00[\xE3\xE4\xE5\xE6\xE7\xE8\xE9]"

# player name in cutscenes. not used at the moment, but holding onto it for now.
# EF ?? 01 ?? ?? ?? ?? 3C EF ?? 01
player_name_cutscenes = rb"\xEF.\x01....\x3C\xEF.\x01"

# "動画配信の際はサーバー" found in notice box on login. Bytes are just the words encoded into utf-8
# E5 8B 95 E7 94 BB E9 85 8D E4 BF A1 E3 81 AE E9 9A 9B E3 81 AF E3 82 B5 E3 83 BC E3 83 90 E3 83 BC
notice_string = rb"\xE5\x8B\x95\xE7\x94\xBB\xE9\x85\x8D\xE4\xBF\xA1\xE3\x81\xAE\xE9\x9A\x9B\xE3\x81\xAF\xE3\x82\xB5\xE3\x83\xBC\xE3\x83\x90\xE3\x83\xBC"
