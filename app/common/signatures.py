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

# function triggered when a quest is accepted and text is displayed on the screen
# this is currently broken because integrity scans pick it up when you get into combat
# 8B 45 D8 3B 45 DC 8B 03 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? ?? CC 48
#    DQXGame.exe.text+BA3C50 - E9 C87E5BFF           - jmp DQXGame.exe.text+15BB1D
# >> DQXGame.exe.text+BA3C55 - 8B 45 D8              - mov eax,[ebp-28]
#    DQXGame.exe.text+BA3C58 - 3B 45 DC              - cmp eax,[ebp-24]
#    DQXGame.exe.text+BA3C5B - 8B 03                 - mov eax,[ebx]
#    DQXGame.exe.text+BA3C5D - 0F85 97DB0800         - jne DQXGame.exe.text+C317FA
#    DQXGame.exe.text+BA3C63 - E9 86D1CF07           - jmp DQXGame.exe.text+670DDEE
#    DQXGame.exe.text+BA3C68 - CC                    - int 3
#    DQXGame.exe.text+BA3C69 - 48                    - dec eax
#    DQXGame.exe.text+BA3C6A - 8D 64 24 FC           - lea esp,[esp-04]
#    DQXGame.exe.text+BA3C6E - 89 04 24              - mov [esp],eax
#    DQXGame.exe.text+BA3C71 - FF 75 94              - push [ebp-6C]
#    DQXGame.exe.text+BA3C74 - 68 F27A3201           - push DQXGame.exe.text+BB6AF2
#    DQXGame.exe.text+BA3C79 - 68 80CC1401           - push DQXGame.exe.text+9DBC80
accept_quest_trigger = rb"\x8B\x45\xD8\x3B\x45\xDC\x8B\x03\x0F\x85....\xE9....\xCC\x48"

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
# 55 8B EC 56 8B F1 57 8B 46 58 85 C0
# >> DQXGame.exe.text+4096C0 - 55                    - push ebp
#    DQXGame.exe.text+4096C1 - 8B EC                 - mov ebp,esp
#    DQXGame.exe.text+4096C3 - 56                    - push esi
#    DQXGame.exe.text+4096C4 - 8B F1                 - mov esi,ecx
#    DQXGame.exe.text+4096C6 - 57                    - push edi
#    DQXGame.exe.text+4096C7 - 8B 46 58              - mov eax,[esi+58]
#    DQXGame.exe.text+4096CA - 85 C0                 - test eax,eax
#    DQXGame.exe.text+4096CC - 74 10                 - je DQXGame.exe.text+4096DE
#    DQXGame.exe.text+4096CE - 50                    - push eax
#    DQXGame.exe.text+4096CF - E8 EC38C3FF           - call DQXGame.exe.text+3CFC0
#    DQXGame.exe.text+4096D4 - 83 C4 04              - add esp,04
#    DQXGame.exe.text+4096D7 - C7 46 58 00000000     - mov [esi+58],00000000
#    DQXGame.exe.text+4096DE - 6A 02                 - push 02
#    DQXGame.exe.text+4096E0 - 68 B0000000           - push 000000B0
#    DQXGame.exe.text+4096E5 - E8 365FC3FF           - call DQXGame.exe.text+3F620
player_sibling_name_trigger = rb"\x55\x8B\xEC\x56\x8B\xF1\x57\x8B\x46\x58\x85\xC0"

# monster and npc names pass through this. we could rename them here and completely
# get rid of name scans.. BUT.. this gets scanned by the integrity check in combat.
# 8B 45 0C 80 38 00 68 ?? ?? ?? ?? 89
# >> DQXGame.exe.text+4FB38C4 - 8B 45 0C              - mov eax,[ebp+0C]
#    DQXGame.exe.text+4FB38C7 - 80 38 00              - cmp byte ptr [eax],00
#    DQXGame.exe.text+4FB38CA - 68 AB083501           - push DQXGame.exe.text+BDF8AB
#    DQXGame.exe.text+4FB38CF - 89 44 24 FC           - mov [esp-04],eax
#    DQXGame.exe.text+4FB38D3 - 8D 64 24 FC           - lea esp,[esp-04]
#    DQXGame.exe.text+4FB38D7 - 8D 64 24 FC           - lea esp,[esp-04]
#    DQXGame.exe.text+4FB38DB - 89 0C 24              - mov [esp],ecx
#    DQXGame.exe.text+4FB38DE - 8B 44 24 08           - mov eax,[esp+08]
#    DQXGame.exe.text+4FB38E2 - B9 600D8200           - mov ecx,DQXGame.exe.text+AFD60
#    DQXGame.exe.text+4FB38E7 - 0F44 C1               - cmove eax,ecx
#    DQXGame.exe.text+4FB38EA - 89 44 24 08           - mov [esp+08],eax
#    DQXGame.exe.text+4FB38EE - 8B 0C 24              - mov ecx,[esp]
#    DQXGame.exe.text+4FB38F1 - 8D 64 24 04           - lea esp,[esp+04]
#    DQXGame.exe.text+4FB38F5 - 8D 64 24 04           - lea esp,[esp+04]
#    DQXGame.exe.text+4FB38F9 - 8B 44 24 FC           - mov eax,[esp-04]
#    DQXGame.exe.text+4FB38FD - 8D 64 24 04           - lea esp,[esp+04]
npc_monster_names_trigger = rb"\x8B\x4E\x04\x83\xC4\x10\x8B\x81"

#############################################
# "Patterns" seen to find various text.
# Not code signatures, so these will likely
# change and need to be updated on patches.
#############################################

# pattern for npc/monsters to rename. (49 bytes)
# npc:     D4 86 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 68 0C ?? ?? ?? ?? ?? ?? A4 0C ?? ?? E?
# monster: D4 86 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 F4 F9 ?? ?? ?? ?? ?? ?? A4 0C ?? ?? E?
# party:   D4 86 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 60 FC ?? ?? ?? ?? ?? ?? A4 0C ?? ?? E?
npc_monster_pattern = rb"\xD4\x86..\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00....\x00.......\x00\x00\x00\x00.\x00\x00\x00[\x68\xF4\x60][\x0C\xF9\xFC]......\xA4\x0C..[\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEF]"

# pattern for concierge names (13 bytes)
# 1C F2 ?? ?? ?? ?? ?? ?? A4 0C ?? ?? E3
concierge_name_pattern = rb"\x1C\xF2......\xA4\x0C..[\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEF]"

# pattern for player names to rename. (49 bytes)
# D4 86 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 48 7D ?? 0? ?? ?? ?? ?? ?? ?? ?? 0? E3
player_name_pattern = rb"\xD4\x86..\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00....\x00...\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x7D.[\x01\x02].......[\x01\x02][\xE3\xEF]"
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
# 90 ?? ?? ?? 00 00 00 00 04 02 00 00 10 00 00 00 E?
walkthrough_pattern = rb"\x90...\x00\x00\x00\x00\x04\x02\x00\x00\x10\x00\x00\x00[\xE3\xE4\xE5\xE6\xE7\xE8\xE9]"

# player name in cutscenes. not used at the moment, but holding onto it for now.
# EF ?? 01 ?? ?? ?? ?? 3C EF ?? 01
player_name_cutscenes = rb"\xEF.\x01....\x3C\xEF.\x01"

# "『ドラゴンクエストX" found in notice box on login. Bytes are just the words encoded into utf-8
# E3 80 8E E3 83 89 E3 83 A9 E3 82 B4 E3 83 B3 E3 82 AF E3 82 A8 E3 82 B9 E3 83 88 58
notice_string = rb"\xE3\x80\x8E\xE3\x83\x89\xE3\x83\xA9\xE3\x82\xB4\xE3\x83\xB3\xE3\x82\xAF\xE3\x82\xA8\xE3\x82\xB9\xE3\x83\x88\x58"