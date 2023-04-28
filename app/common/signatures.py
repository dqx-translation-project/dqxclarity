#############################################
# DQX functions that shouldn't change much
# as these are code signatures.
#############################################

# takes you to the section of the function where you can read where dialog is stored before
# it's rendered to screen. captures npc text.
# FF 77 08 C7 45 FC ?? ?? ?? ?? BB
# 8D 64 24 FC 89 04 24 8D 64 24 FC E9 ?? ?? ?? ?? 3B -- better, but picked up by integrity scans in combat.
dialog_trigger = rb"\xFF\x77\x08\xC7\x45\xFC....\xBB"

# function that is triggered when a quest window opens. used for translating quest text
# 8D 8E 78 04 00 00 E8 ?? ?? ?? ?? 5F
quest_text_trigger = rb"\x8D\x8E\x78\x04\x00\x00\xE8....\x5F"

# Integrity check + hooking addresses
# 52 57 51 50 53 56
integrity_check = rb"\x52\x57\x51\x50\x53\x56"

# If we ever figure out how to go undetected with scans, this will translate
# party names for us without scanning.
# 8B CF FF 75 0C 53 50
menu_party_name_trigger = rb"\x8B\xCF\xFF\x75\x0C\x53\x50"

# function triggered when a quest is accepted and text is displayed on the screen
# 8B 45 D8 3B 45 DC 8B 03 75 DE 56 FF 50 6C
accept_quest_trigger = rb"\x8B\x45\xD8\x3B\x45\xDC\x8B\x03\x75\xDE\x56\xFF\x50\x6C"

#############################################
# "Patterns" seen to find various text.
# Not code signatures, so these will likely
# change and need to be updated on patches.
#############################################

# pattern for npc/monsters to rename. (49 bytes) 
# npc:     70 73 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 7C E6 ?? ?? ?? ?? ?? ?? 60 ED ?? ?? E?
# monster: 70 73 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 30 D4 ?? ?? ?? ?? ?? ?? 60 ED ?? ?? E?
# party:   70 73 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 98 D6 ?? ?? ?? ?? ?? ?? 60 ED ?? ?? E?
npc_monster_pattern = rb"\x70\x73..\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00....\x00.......\x00\x00\x00\x00.\x00\x00\x00[\x7C\x30\x98][\xE6\xD4\xD6]......\x60\xED..[\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEF]"

# pattern for concierge names (13 bytes)
# 34 CD ?? ?? ?? ?? ?? ?? 60 ED ?? ?? E?
concierge_name_pattern = rb"\x34\xCD......\x60\xED..[\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEF]"

# pattern for player names to rename. (49 bytes)
# 70 73 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 90 51 ?? 0? ?? ?? ?? ?? ?? ?? ?? 0? E?
player_name_pattern = rb"\x70\x73..\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00....\x00...\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\x51.[\x01\x02].......[\x01\x02][\xE3\xEF]"

# pattern for sibling names to rename. (52 bytes)
# 01 ?? 00 ?? 00 00 00 ?? ?? 00 02 ?? 00 ?? 00 ?? 00 00 00 00 00 ?? 00 00 00 00 00 ?? ?? ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? ?? 00 00 00 00 ?? ?? 00 00 00 00 E?
sibling_name_pattern = rb"\x01.\x00.\x00\x00\x00..\x00\x02.\x00.\x00.\x00\x00\x00\x00\x00.\x00\x00\x00\x00\x00...\x00.\x00...\x00.\x00..\x00\x00\x00\x00..\x00\x00\x00\x00[\xE3\xEF]"

# pattern for menu ai to rename. (58 bytes)
# 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? ?? ?? 00 00 00 ?? 1? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? E?
menu_ai_name_pattern = rb"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00...........\x00..\x00\x00.....\x00\x00\x00.[\x1B\x1C].....\x00.....\x00..[\xE3\xEF]"

# pattern for master quests.
# ?0 ?? ?? ?? ?0 00 00 00 ?0 ?? ?? 0? E?
master_quest_pattern = rb"[\x10\x20\x30\x40\x50\x60\x70\x80\x90\xA0\xB0\xC0\xD0\xE0\xF0]...[\x10\x20\x30\x40\x50]\x00\x00\x00[\x00\x10\x20\x30\x40\x50\x60\x70\x80\x90\xA0\xB0\xC0\xD0\xE0\xF0]..[\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F][\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEF]"

# pattern for projector names to rename.
# 20 00 00 00 ?? ?? ?? 0A E?
# projector_name_byte_pattern = rb'\x20\x00\x00\x00...\x0A[\xE3\xE4\xE5\xE6\xE7\xE8\xE9]'

# Main walkthrough text that loads on login. I can't figure out what function loads this on login,
# so scanning for this for now. AC is also preventing this from just being accessible via hooks. (17 bytes)
# A0 ?? ?? ?? 00 00 00 00 04 02 00 00 10 00 00 00 E?
walkthrough_pattern = rb"\xA0...\x00\x00\x00\x00\x04\x02\x00\x00\x10\x00\x00\x00[\xE3\xE4\xE5\xE6\xE7\xE8\xE9]"
