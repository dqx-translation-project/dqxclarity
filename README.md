# dqxclarity

A translation utility for the game "Dragon Quest X".

## What does this tool do?

`dqxclarity` is written in Python and intercepts/scans game functions and text in memory and replaces text with English using a supported machine translation service. `dqxclarity` only live translates text that comes from DQX servers, which includes:

- Talking to NPCs that have no other purpose than filler
- Quest text
- NPC / monster names

All text that isn't pulled from DQX servers lives in the DQX game files. A modified `dat` file is provided in the [releases](https://github.com/dqx-translation-project/dqxclarity/releases/latest) section that should be used alongside `dqxclarity` for the best English experience. This dat contains translated files that are used in place of the Japanese files.

## Installation

**It's recommended you install both of these for the best translated experience.**

## `dqxclarity` (live translation)

- Download the latest `dqxclarity.zip` file from the [releases](https://github.com/dqx-translation-project/dqxclarity/releases/latest) section
- Unzip `dqxclarity.zip` somewhere that **isn't** in `Program Files` (desktop, documents, etc.)
- Open the extracted `dqxclarity` folder and double-click `DQXClarity.exe` to run

**Note that this will prompt you to install Python 3.11.3 32-bit if you don't have it installed for all users.**

[Read the wiki if you still need help](https://github.com/dqxtranslationproject/dqxclarity/wiki)

## DAT installation

- Download the `data00000000.win32.dat0` and `data00000000.win32.idx` file from the [releases](https://github.com/dqx-translation-project/dqxclarity/releases/latest) section
- Navigate to the directory where you installed DQX
    - By default, this is in `C:\Program Files (x86)\SquareEnix\DRAGON QUEST X`
- Inside of this folder, browse to `Game\Content\Data`
- Back up your existing `data00000000.win32.dat0` and `data00000000.win32.idx` files (rename them both with a `.bak` extension or something)
- Move the downloaded `data00000000.win32.dat0` and `data00000000.win32.idx` files into this directory
- Launch the game


## Disclaimer

**I forfeit any responsibility if you receive a warning, a ban or a stern talking to while using this program. `dqxclarity` alters process memory, but only for the intent of allowing English-speaking players to read the game in their language. No malicious activities are being performed with `dqxclarity`. The goal of this program is simply to translate the game for non-Japanese speaking players to enjoy.**
