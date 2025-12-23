# fmt: off
#############################################
# DQX functions that shouldn't change much
# as these are code signatures.
#############################################

# 55 8B EC 53 57 8B 79 24 85 FF 74 ?? 83 7D 08 00
blowfish_logger_trigger = rb"\x55\x8B\xEC\x53\x57\x8B\x79\x24\x85\xFF\x74.\x83\x7D\x08\x00"

# 55 8B EC 8B 55 08 85 D2 75 04 33 C0 5D C3 53
# hash_logger_start_trigger = rb"\x55\x8B\xEC\x8B\x55\x08\x85\xD2\x75\x04\x33\xC0\x5D\xC3\x53"

# 42 83 EF 01 75 ?? 5F 5E 8B C1 5B 5D C3
hash_logger_end_trigger = rb"\x42\x83\xEF\x01\x75.\x5F\x5E\x8B\xC1\x5B\x5D\xC3"

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

# a lot of network text that is drawn to the screen comes through this function
# 8B CA 8D 71 ?? 8A 01 41 84 C0 75 F9 EB 20
#    DQXGame.exe+526905 - 75 E9                 - jne DQXGame.exe+5268F0
#    DQXGame.exe+526907 - 83 BD 78FCFFFF 0F     - cmp dword ptr [ebp-00000388],0F
#    DQXGame.exe+52690E - 8D 95 64FCFFFF        - lea edx,[ebp-0000039C]
#    DQXGame.exe+526914 - 0F47 95 64FCFFFF      - cmova edx,[ebp-0000039C]
# >> DQXGame.exe+52691B - 8B CA                 - mov ecx,edx
# >> DQXGame.exe+52691D - 8D 71 01              - lea esi,[ecx+01]
# >> DQXGame.exe+526920 - 8A 01                 - mov al,[ecx]
# >> DQXGame.exe+526922 - 41                    - inc ecx
# >> DQXGame.exe+526923 - 84 C0                 - test al,al
# >> DQXGame.exe+526925 - 75 F9                 - jne DQXGame.exe+526920
# >> DQXGame.exe+526927 - EB 20                 - jmp DQXGame.exe+526949
#    DQXGame.exe+526929 - 83 BD 78FCFFFF 0F     - cmp dword ptr [ebp-00000388],0F
#    DQXGame.exe+526930 - 8D 95 64FCFFFF        - lea edx,[ebp-0000039C]
network_text_trigger = rb"\x8B\xCA\x8D\x71.\x8A\x01\x41\x84\xC0\x75\xF9\xEB\x20"

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
#    DQXGame.exe+717D70 - 55                    - push ebp
#    DQXGame.exe+717D71 - 8B EC                 - mov ebp,esp
#    DQXGame.exe+717D73 - 8B 45 10              - mov eax,[ebp+10]
#    DQXGame.exe+717D76 - 83 EC 14              - sub esp,14
#    DQXGame.exe+717D79 - 53                    - push ebx
#    DQXGame.exe+717D7A - 8B 5D 14              - mov ebx,[ebp+14]
#    DQXGame.exe+717D7D - 56                    - push esi
#    DQXGame.exe+717D7E - 8B F1                 - mov esi,ecx
#    DQXGame.exe+717D80 - 57                    - push edi
#    DQXGame.exe+717D81 - 85 C0                 - test eax,eax
#    DQXGame.exe+717D83 - 0F84 16020000         - je DQXGame.exe+717F9F
# >> DQXGame.exe+717D89 - 8B D0                 - mov edx,eax
# >> DQXGame.exe+717D8B - 8D 7A 01              - lea edi,[edx+01]
# >> DQXGame.exe+717D8E - 66 90                 - nop 2
# >> DQXGame.exe+717D90 - 8A 0A                 - mov cl,[edx]
# >> DQXGame.exe+717D92 - 42                    - inc edx
# >> DQXGame.exe+717D93 - 84 C9                 - test cl,cl
# >> DQXGame.exe+717D95 - 75 F9                 - jne DQXGame.exe+717D90
# >> DQXGame.exe+717D97 - 2B D7                 - sub edx,edi
# >> DQXGame.exe+717D99 - 0F84 00020000         - je DQXGame.exe+717F9F
# >> DQXGame.exe+717D9F - 51                    - push ecx
#    DQXGame.exe+717DA0 - 8B CC                 - mov ecx,esp
#    DQXGame.exe+717DA2 - 89 01                 - mov [ecx],eax
#    DQXGame.exe+717DA4 - 8D 45 F0              - lea eax,[ebp-10]
#    DQXGame.exe+717DA7 - 50                    - push eax
#    DQXGame.exe+717DA8 - 8B CE                 - mov ecx,esi
# 8B D0 8D ?? 01 66 90 8A 0A 42 84 C9 75 F9 2B ?? 0F 84 ?? ?? ?? ?? 51
corner_text_trigger = (
    rb"\x8B\xD0\x8D.\x01\x66\x90\x8A\x0A\x42\x84\xC9\x75\xF9\x2B.\x0F\x84....\x51"
)

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

# to find this, search for walkthrough text:
# メインコマンド『せんれき』の
# ^ is text when you are caught up with the story.
# you are looking for the original source string that is read,
# not the ones that are just written to the screen. to figure
# this out, with the command window closed, update the first
# jp letter with "eee", then open the window. if the window
# shows "eee", then put a "what reads this" breakpoint here.
# should be the entry, "mov al, [ecx]". it should only trigger
# when the command window opens, that's it. from there, go down
# a few instructions and look for a clean place to hook.
#    DQXGame.exe+2DDA9D - 8D B8 EC000000        - lea edi,[eax+000000EC]
#    DQXGame.exe+2DDAA3 - 8B CF                 - mov ecx,edi
#    DQXGame.exe+2DDAA5 - 8D 51 01              - lea edx,[ecx+01]
# >> DQXGame.exe+2DDAA8 - 8A 01                 - mov al,[ecx] (breakpoint hits here!)
#    DQXGame.exe+2DDAAA - 41                    - inc ecx
#    DQXGame.exe+2DDAAB - 84 C0                 - test al,al
#    DQXGame.exe+2DDAAD - 75 F9                 - jne DQXGame.exe+2DDAA8
#    DQXGame.exe+2DDAAF - 2B CA                 - sub ecx,edx
#    DQXGame.exe+2DDAB1 - 0F84 FF000000         - je DQXGame.exe+2DDBB6
# >> DQXGame.exe+2DDAB7 - 57                    - push edi (we hook here!)
# >> DQXGame.exe+2DDAB8 - 8B F7                 - mov esi,edi
# >> DQXGame.exe+2DDABA - BB 01000000           - mov ebx,00000001
#    DQXGame.exe+2DDABF - E8 3C89E0FF           - call DQXGame.exe+E6400
#    DQXGame.exe+2DDAC4 - 83 C4 04              - add esp,04
#    DQXGame.exe+2DDAC7 - 83 F8 05              - cmp eax,05
#    DQXGame.exe+2DDACA - 77 25                 - ja DQXGame.exe+2DDAF1
#    DQXGame.exe+2DDACC - 0F1F 40 00            - nop dword ptr [eax+00]
# 57 8B F7 BB
walkthrough_trigger = rb"\x57\x8B\xF7\xBB"

# - find a player
# - on the first byte of their name, put a "break on write"
# - can take a while to hit.. a player has to leave and a new player
#   has to take that spot. it can take a while...
# - click run on the first hit
# - step through until you're out of the loop
# >> DQXGame.exe+7211B4F - 8B 47 04              - mov eax,[edi+04]
# >> DQXGame.exe+7211B52 - 8B 88 88010000        - mov ecx,[eax+00000188]
#    DQXGame.exe+7211B58 - 85 C9                 - test ecx,ecx
#    DQXGame.exe+7211B5A - 68 FDFDBA02           - push DQXGame.exe+2B8FDFD
#    DQXGame.exe+7211B5F - 89 54 24 FC           - mov [esp-04],edx
#    DQXGame.exe+7211B63 - 8D 64 24 FC           - lea esp,[esp-04]
#    DQXGame.exe+7211B67 - 8D 64 24 FC           - lea esp,[esp-04]
#    DQXGame.exe+7211B6B - 89 1C 24              - mov [esp],ebx
#    DQXGame.exe+7211B6E - 8B 54 24 08           - mov edx,[esp+08]
#    DQXGame.exe+7211B72 - BB 499F1700           - mov ebx,DQXGame.exe+159F49
#    DQXGame.exe+7211B77 - 0F44 D3               - cmove edx,ebx
#    DQXGame.exe+7211B7A - 89 54 24 08           - mov [esp+08],edx
#    DQXGame.exe+7211B7E - 8B 1C 24              - mov ebx,[esp]
#    DQXGame.exe+7211B81 - 8D 64 24 04           - lea esp,[esp+04]
#    DQXGame.exe+7211B85 - 8D 64 24 04           - lea esp,[esp+04]
#    DQXGame.exe+7211B89 - 8B 54 24 FC           - mov edx,[esp-04]
#    DQXGame.exe+7211B8D - 8D 64 24 04           - lea esp,[esp+04]
# 8B 47 04 8B 88 88 01 00 00
nameplates_trigger = rb"\x8B\x47\x04\x8B\x88\x88\x01\x00\x00"

# - talk to some purple npc that has a quest
# - when the quest comes up, copy some text from it
# - search for it
# - find what accesses it
# this covers accepting a quest and quests from the map.
# might change between patches unfortunately.
#    DQXGame.exe+2473E0 - 55                    - push ebp
#    DQXGame.exe+2473E1 - 8B EC                 - mov ebp,esp
#    DQXGame.exe+2473E3 - 53                    - push ebx
#    DQXGame.exe+2473E4 - 8B 5D 08              - mov ebx,[ebp+08]
#    DQXGame.exe+2473E7 - 56                    - push esi
#    DQXGame.exe+2473E8 - 8B F1                 - mov esi,ecx
#    DQXGame.exe+2473EA - 57                    - push edi
#    DQXGame.exe+2473EB - 8B 03                 - mov eax,[ebx]
#    DQXGame.exe+2473ED - BF 38000000           - mov edi,00000038 { 56 }
#    ....
#    ....
#    DQXGame.exe+2474E0 - 0FB6 83 56030000      - movzx eax,byte ptr [ebx+00000356]
#    DQXGame.exe+2474E7 - 88 86 56030000        - mov [esi+00000356],al
#    DQXGame.exe+2474ED - 0FB6 83 57030000      - movzx eax,byte ptr [ebx+00000357]
#    DQXGame.exe+2474F4 - 5F                    - pop edi
# >> DQXGame.exe+2474F5 - 88 86 57030000        - mov [esi+00000357],al
# >> DQXGame.exe+2474FB - 5E                    - pop esi
# >> DQXGame.exe+2474FC - 5B                    - pop ebx
# >> DQXGame.exe+2474FD - 5D                    - pop ebp
# >> DQXGame.exe+2474FE - C2 0400               - ret 0004
# 88 86 57 03 00 00 5E 5B 5D C2 04 00
accept_quest_text_trigger = rb"\x88\x86\x57\x03\x00\x00\x5E\x5B\x5D\xC2\x04\x00"

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
