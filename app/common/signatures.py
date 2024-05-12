#############################################
# DQX functions that shouldn't change much
# as these are code signatures.
#############################################

# takes you to the section of the function where you can read where dialog is stored before
# it's rendered to screen. captures npc text.
# FF 77 08 C7 45
#    DQXGame.exe.text+432093 - 51                    - push ecx
#    DQXGame.exe.text+432094 - 89 01                 - mov [ecx],eax
#    DQXGame.exe.text+432096 - 8B C4                 - mov eax,esp
#    DQXGame.exe.text+432098 - 89 30                 - mov [eax],esi
#    DQXGame.exe.text+43209A - E8 41B8FFFF           - call DQXGame.exe.text+42D8E0
# >> DQXGame.exe.text+43209F - FF 77 08              - push [edi+08]
#    DQXGame.exe.text+4320A2 - C7 45 F0 00000000     - mov [ebp-10],00000000
#    DQXGame.exe.text+4320A9 - C7 45 F4 FDFFFFFF     - mov [ebp-0C],FFFFFFFD
#    DQXGame.exe.text+4320B0 - E8 CB0BC6FF           - call DQXGame.exe.text+92C80
#    DQXGame.exe.text+4320B5 - 8B 15 18160D02        - mov edx,[DQXGame.exe+2011618]
#    DQXGame.exe.text+4320BB - 83 C4 14              - add esp,14
#    DQXGame.exe.text+4320BE - 89 45 F8              - mov [ebp-08],eax
dialog_trigger = rb"\xFF\x77\x08\xC7\x45"

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
# 52 57 51 50 53 56
# >> DQXGame.exe.text+DF049B - 52                    - push edx
#    DQXGame.exe.text+DF049C - 57                    - push edi
#    DQXGame.exe.text+DF049D - 51                    - push ecx
#    DQXGame.exe.text+DF049E - 50                    - push eax
#    DQXGame.exe.text+DF049F - 53                    - push ebx
#    DQXGame.exe.text+DF04A0 - 56                    - push esi
#    DQXGame.exe.text+DF04A1 - 8D 64 24 80           - lea esp,[esp--80]
#    DQXGame.exe.text+DF04A5 - 66 0F11 3C 24         - movupd [esp],xmm7
#    DQXGame.exe.text+DF04AA - 66 0F11 64 24 10      - movupd [esp+10],xmm4
#    DQXGame.exe.text+DF04B0 - 66 0F11 44 24 20      - movupd [esp+20],xmm0
#    DQXGame.exe.text+DF04B6 - 66 0F11 4C 24 30      - movupd [esp+30],xmm1
#    DQXGame.exe.text+DF04BC - 66 0F11 54 24 40      - movupd [esp+40],xmm2
#    DQXGame.exe.text+DF04C2 - 66 0F11 6C 24 50      - movupd [esp+50],xmm5
#    DQXGame.exe.text+DF04C8 - 66 0F11 74 24 60      - movupd [esp+60],xmm6
#    DQXGame.exe.text+DF04CE - 66 0F11 5C 24 70      - movupd [esp+70],xmm3
#    DQXGame.exe.text+DF04D4 - E9 BF2754FD           - jmp DQXGame.exe.text+4C5C98
integrity_check = rb"\x52\x57\x51\x50\x53\x56"

# If we ever figure out how to go undetected with scans, this will translate
# party names for us without scanning.
# 8B CF FF 75 0C 53 50
#    DQXGame.exe.text+E6B98 - 8B E5                 - mov esp,ebp
#    DQXGame.exe.text+E6B9A - 5D                    - pop ebp
#    DQXGame.exe.text+E6B9B - C2 1000               - ret 0010
#    DQXGame.exe.text+E6B9E - FF 75 10              - push [ebp+10]
# >> DQXGame.exe.text+E6BA1 - 8B CF                 - mov ecx,edi
#    DQXGame.exe.text+E6BA3 - FF 75 0C              - push [ebp+0C]
#    DQXGame.exe.text+E6BA6 - 53                    - push ebx
#    DQXGame.exe.text+E6BA7 - 50                    - push eax
#    DQXGame.exe.text+E6BA8 - E8 43D3FFFF           - call DQXGame.exe.text+E3EF0
#    DQXGame.exe.text+E6BAD - 8B 4D FC              - mov ecx,[ebp-04]
#    DQXGame.exe.text+E6BB0 - 5F                    - pop edi
#    DQXGame.exe.text+E6BB1 - 5E                    - pop esi
#    DQXGame.exe.text+E6BB2 - 33 CD                 - xor ecx,ebp
menu_party_name_trigger = rb"\x8B\xCF\xFF\x75\x0C\x53\x50"

# a lot of network text that is drawn to the screen comes through this function
# 8D 71 01 8B FF 8A 01 41 84 C0 75 F9 2B CE 51 51
#    DQXGame.exe.text+42DF02 - 4E                    - dec esi
#    DQXGame.exe.text+42DF03 - 75 EB                 - jne DQXGame.exe.text+42DEF0
#    DQXGame.exe.text+42DF05 - 83 BD 70FDFFFF 10     - cmp dword ptr [ebp-00000290],10
#    DQXGame.exe.text+42DF0C - 8D 95 5CFDFFFF        - lea edx,[ebp-000002A4]
#    DQXGame.exe.text+42DF12 - 0F43 95 5CFDFFFF      - cmovae edx,[ebp-000002A4]
#    DQXGame.exe.text+42DF19 - 8B CA                 - mov ecx,edx
# >> DQXGame.exe.text+42DF1B - 8D 71 01              - lea esi,[ecx+01]
#    DQXGame.exe.text+42DF1E - 8B FF                 - mov edi,edi
#    DQXGame.exe.text+42DF20 - 8A 01                 - mov al,[ecx]
#    DQXGame.exe.text+42DF22 - 41                    - inc ecx
#    DQXGame.exe.text+42DF23 - 84 C0                 - test al,al
#    DQXGame.exe.text+42DF25 - 75 F9                 - jne DQXGame.exe.text+42DF20
#    DQXGame.exe.text+42DF27 - 2B CE                 - sub ecx,esi
#    DQXGame.exe.text+42DF29 - 51                    - push ecx
#    DQXGame.exe.text+42DF2A - 51                    - push ecx
#    DQXGame.exe.text+42DF2B - 8B C4                 - mov eax,esp
#    DQXGame.exe.text+42DF2D - 89 10                 - mov [eax],edx
#    DQXGame.exe.text+42DF2F - EB 79                 - jmp DQXGame.exe.text+42DFAA
network_text_trigger = rb"\x8D\x71\x01\x8B\xFF\x8A\x01\x41\x84\xC0\x75\xF9\x2B\xCE\x51\x51"

# player and sibling names on login. use this to figure out what the player is logged in as
# 55 8B EC 56 8B F1 57 8B 46 60 85 C0
#    DQXGame.exe.text+421150 - 55                    - push ebp
#    DQXGame.exe.text+421151 - 8B EC                 - mov ebp,esp
#    DQXGame.exe.text+421153 - 56                    - push esi
#    DQXGame.exe.text+421154 - 8B F1                 - mov esi,ecx
#    DQXGame.exe.text+421156 - 57                    - push edi
#    DQXGame.exe.text+421157 - 8B 46 60              - mov eax,[esi+60]
#    DQXGame.exe.text+42115A - 85 C0                 - test eax,eax
#    DQXGame.exe.text+42115C - 74 10                 - je DQXGame.exe.text+42116E
#    DQXGame.exe.text+42115E - 50                    - push eax
#    DQXGame.exe.text+42115F - E8 CCC1C1FF           - call DQXGame.exe.text+3D330
#    DQXGame.exe.text+421164 - 83 C4 04              - add esp,04
#    DQXGame.exe.text+421167 - C7 46 60 00000000     - mov [esi+60],00000000
#    DQXGame.exe.text+42116E - 6A 02                 - push 02
#    DQXGame.exe.text+421170 - 68 B0000000           - push 000000B0
#    DQXGame.exe.text+421175 - E8 C6C1C1FF           - call DQXGame.exe.text+3D340
player_sibling_name_trigger = rb"\x55\x8B\xEC\x56\x8B\xF1\x57\x8B\x46\x60\x85\xC0"

# party member data hits this code. used to detour and overwrite name.
# how it was found:
# - Search in CE for one of your party members
#   - Must be actual player entry - not just name
# - "Find what writes here" on the name
# - Used instructions right below "repe movsd" instruction
# DQXGame.exe+5B7133 - F3 0F10 05 94F61601   - movss xmm0,[DQXGame.exe+E4F694]
# DQXGame.exe+5B713B - 0F2F C1               - comiss xmm0,xmm1
# DQXGame.exe+5B713E - 72 0C                 - jb DQXGame.exe+5B714C
# DQXGame.exe+5B7140 - BE 01000000           - mov esi,00000001
# DQXGame.exe+5B7145 - EB 05                 - jmp DQXGame.exe+5B714C
# DQXGame.exe+5B7147 - BE 03000000           - mov esi,00000003
# DQXGame.exe+5B714C - 3B FE                 - cmp edi,esi
# DQXGame.exe+5B714E - B9 BE000000           - mov ecx,000000BE
# DQXGame.exe+5B7153 - 8B 75 08              - mov esi,[ebp+08]
# DQXGame.exe+5B7156 - 8D 7B 28              - lea edi,[ebx+28]
# DQXGame.exe+5B7159 - F3 A5                 - repe movsd
party_ai_trigger = rb"\x8B\x8B\xC8\x05\x00\x00"

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
#    DQXGame.exe.text+601020 - 55                    - push ebp
#    DQXGame.exe.text+601021 - 8B EC                 - mov ebp,esp
#    DQXGame.exe.text+601023 - 8B 45 08              - mov eax,[ebp+08]
#    DQXGame.exe.text+601026 - 83 EC 10              - sub esp,10
#    DQXGame.exe.text+601029 - 53                    - push ebx
#    DQXGame.exe.text+60102A - 56                    - push esi
#    DQXGame.exe.text+60102B - 8B F1                 - mov esi,ecx
#    DQXGame.exe.text+60102D - 57                    - push edi
#    DQXGame.exe.text+60102E - 85 C0                 - test eax,eax
#    DQXGame.exe.text+601030 - 0F84 A1010000         - je DQXGame.exe.text+6011D7
# >> DQXGame.exe.text+601036 - 8B D0                 - mov edx,eax
#    DQXGame.exe.text+601038 - 8D 7A 01              - lea edi,[edx+01]
#  8B D0 8D 7A 01 EB 03 8D 49 00 8A 0A 42 84 C9 75 F9 2B D7 0F 84 ?? ?? ?? ?? 51
corner_text_trigger = rb"\x8B\xD0\x8D\x7A\x01\xEB\x03\x8D\x49\x00\x8A\x0A\x42\x84\xC9\x75\xF9\x2B\xD7\x0F\x84....\x51"

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
# npc:     BC 6B ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 B8 EF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E?
# monster: BC 6B ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 14 DD ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E?
# party:   BC 6B ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 88 DF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E?
npc_monster_pattern = rb"\x0C\x8A..\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00....\x00.......\x00\x00\x00\x00.\x00\x00\x00[\xB8\x14\x88][\xEF\xDD\xDF]..........[\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEF]"

# pattern for concierge names (13 bytes)
# 90 8B ?? ?? ?? ?? ?? ?? A0 4B ?? ?? E?
concierge_name_pattern = rb"\x90\x8B......\xA0\xFB..[\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEF]"

# pattern for player names to rename. (49 bytes)
# BC 6B ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 B8 C5 ?? 0? ?? ?? ?? ?? ?? ?? ?? 0? E?
player_name_pattern = rb"\xBC\x6B..\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00....\x00...\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xB8\xC5.[\x01\x02].......[\x01\x02][\xE3\xEF]"
# pattern for sibling names to rename. (52 bytes)
# 0? ?? 00 ?? 00 00 00 ?? ?? 00 02 ?? 00 ?? 00 ?? 00 00 00 00 00 ?? 00 ?? ?? 00 00 ?? ?? ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? ?? 00 00 00 00 ?? ?? 00 00 00 00 E?
sibling_name_pattern = rb"[\x01\x02].\x00.\x00\x00\x00..\x00\x02.\x00.\x00.\x00\x00\x00\x00\x00.\x00..\x00\x00...\x00.\x00...\x00.\x00..\x00\x00\x00\x00..\x00\x00\x00\x00[\xE3\xEF]"

# pattern for menu ai to rename. (58 bytes)
# 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? ?? ?? 00 00 00 ?? 1? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? E?
menu_ai_name_pattern = rb"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00...........\x00..\x00\x00.....\x00\x00\x00.[\x1B\x1C].....\x00.....\x00..[\xE3\xEF]"

# pattern for comm_names.
# 2? E? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 0F 00 00 00 01 02 00 00 01 00 00
comm_name_pattern_1 = rb"[\xE3\xEF].................\x00\x00\x0F\x00\x00\x00\x01\x02\x00\x00\x01\x00\x00"
# 09 E? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4? 38 00 00 00
comm_name_pattern_2 = rb"\x09[\xE3\xEF].................\x00.................\x38\x00\x00\x00"

# Main walkthrough text that loads on login. I can't figure out what function loads this on login,
# so scanning for this for now. AC is also preventing this from just being accessible via hooks. (17 bytes)
# 30 ?? ?? ?? 00 00 00 00 04 02 00 00 10 00 00 00 E?
walkthrough_pattern = rb"\x30...\x00\x00\x00\x00\x04\x02\x00\x00\x10\x00\x00\x00[\xE3\xE4\xE5\xE6\xE7\xE8\xE9]"

# player name in cutscenes. not used at the moment, but holding onto it for now.
# EF ?? 01 ?? ?? ?? ?? 3C EF ?? 01
player_name_cutscenes = rb"\xEF.\x01....\x3C\xEF.\x01"

# "動画・生配信・画像投稿" found in notice box on login. Bytes are just the words encoded into utf-8
# E5 8B 95 E7 94 BB E3 83 BB E7 94 9F E9 85 8D E4 BF A1 E3 83 BB E7 94 BB E5 83 8F E6 8A 95 E7 A8 BF
notice_string = rb"\xE5\x8B\x95\xE7\x94\xBB\xE3\x83\xBB\xE7\x94\x9F\xE9\x85\x8D\xE4\xBF\xA1\xE3\x83\xBB\xE7\x94\xBB\xE5\x83\x8F\xE6\x8A\x95\xE7\xA8\xBF"
