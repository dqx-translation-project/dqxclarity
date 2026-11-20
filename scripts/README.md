# dqxclarity local build & language pack guide

Helper scripts for building and packaging dqxclarity locally. The application is C#/.NET 9 (Avalonia) in `DqxClarity/`; there is no Python runtime anymore.

## Main edit points

- `DqxClarity/Views/*.axaml`: screens and layout.
- `DqxClarity/Styles/*.axaml`: shared colors, button styles, text styles.
- `DqxClarity/Assets/*`: bundled images and icon.
- `DqxClarity/ViewModels/*`: UI state, commands, tab behavior.
- `DqxClarity/Services/*`: config, patching, launching, language packs, direct login.
- `DqxClarity/Hooking/*`: native DLL injection, pipe IPC, log tailing.
- `DqxClarity/Packets/*`: packet parsing, routing, and per-packet translators.
- `DqxClarity/Translation/*`: translation pipeline, backends, glossary, romanizer.
- `DqxClarity/native/*`: C/C++ hooks (`LocaleHook`, `PacketWarden`), the `version.dll` proxy, and the Rust `wanakana` crate.
- `app/updater.py`: one-time migration updater fetched by old 5.x Python installs. Leave it in place.

## Build the exe

From the repository root:

```powershell
.\scripts\build-launcher.ps1
```

Output:

```text
DqxClarity\bin\Release\net9.0-windows\win-x64\publish\dqxclarity.exe
```

This builds, in order: `LocaleHook.dll` + `PacketWarden.dll` (CMake + Visual Studio Build Tools, C++ desktop workload), `wanakana.dll` (Rust, `rustup target add x86_64-pc-windows-msvc`), then publishes a self-contained single-file exe (no .NET install needed on the user's machine). The DLLs are embedded into the exe, and a missing DLL is skipped silently by the project file, so a build without them still works but loses that feature (no packet hook, no romaji names).

Switches:

- `-SkipNative`: don't rebuild `LocaleHook.dll` / `PacketWarden.dll` (UI-only work).
- `-SkipWanakana`: don't rebuild `wanakana.dll`.
- `-NoRestore`, `-Configuration Debug|Release`.

Remember to rebuild `PacketWarden.dll` whenever a new packet route is added, since its `KNOWN_PACKETS` allowlist is compiled in.

## Build a local distributable folder

```powershell
.\scripts\package-local.ps1
```

Output:

```text
local-build\dqxclarity\
local-build\dqxclarity-mod.zip
```

The folder has the same layout as the release zip: `dqxclarity.exe`, `version.update`, and `misc_files\clarity_dialog.db`. `user_settings.ini` is created by the app on first run, next to the exe.

## Language pack format (CLPK)

A language pack is a **CLPK** container — a small metadata header in front of a ZIP payload:

```text
offset  size  field
0       4     "CLPK"   magic
4       1     0x01     format version
5       2     u16      JSON length N (big-endian)
7       N     JSON     metadata
7+N     ...   ZIP      payload (the sha covers this byte range)
```

Header metadata:

```json
{
  "sha": "<lowercase hex SHA-256 of the zip payload>",
  "language": "en",
  "author": "Your name",
  "builtAt": 1782620310
}
```

- `language` is an ISO code (`en`, `fr`, …). dqxclarity shows its display name (English, French) via `CultureInfo` and uses it as the pack's identity.
- `builtAt` is a Unix timestamp (seconds); shown as the pack's "updated" date.
- `sha` is the SHA-256 of the ZIP payload, verified on download.
- `download_url` (optional) — a self-describing update URL. When a pack omits it, dqxclarity uses the catalog's URL for that language to check for updates.

Optional text settings, for packs meant to be used with a game mod that can display accented characters and resize the dialogue box. Leave them out for the defaults; dqxclarity reads them from the highest-priority active pack each time Run is clicked:

```json
{
  "disable_text_normalization": true,
  "max_chars_per_line": 60,
  "max_lines_per_box": 4
}
```

- `disable_text_normalization` — `true` keeps machine-translated text as the translation service returned it (ñ, é, ü, …). By default it is reduced to plain ASCII, because the unmodded game can't draw those characters.
- `max_chars_per_line` — characters per line in the NPC dialogue box. Default 46; accepted range 10–200.
- `max_lines_per_box` — lines in one dialogue box before the text continues on the next page. Default 3; accepted range 1–20.

A value outside its range is ignored and the default is used. These settings affect machine-translated text only; translations already saved in `clarity_dialog.db` keep the shape they were saved with.

Optional custom translations source:

```json
{
  "custom_translations_url": "https://github.com/my-org/my-custom-translations"
}
```

- `custom_translations_url` — a GitHub repo to download server-side translations from instead of [dqx-custom-translations](https://github.com/dqx-translation-project/dqx-custom-translations). The repo must use the same folders and file names. dqxclarity downloads the zip of its `main` branch (a `/tree/<branch>` link picks another branch); `https://github.com/<repo>` with no organization means `dqx-translation-project/<repo>`. Left out, blank, or not a GitHub repo link: the default repo is used.

### Bundled name files

A pack can include its own copies of the six name files dqxclarity otherwise downloads from [dqx_translations](https://github.com/dqx-translation-project/dqx_translations) (`json/_lang/en/`): `subPackage02Client.json` (monsters), `smldt_msg_pkg_NPC_DB.json` (NPCs), `subPackage05Client.json` (items), `subPackage41Client.json` (key items), `eventTextSysQuestaClient.json` (quests) and `eventTextSysEventaClient.json` (story names). Put them in a `dqxclarity/json/` folder at the root of the ZIP, under those file names. dqxclarity reads them from the highest-priority active pack instead of downloading them, so names in menus, lists and other packets match the pack's language. Any file the pack doesn't include is downloaded as before. The `dqxclarity/` folder is never extracted into `Game\mods`.

### Bundled custom translations

A pack can also include its own copy of [dqx-custom-translations](https://github.com/dqx-translation-project/dqx-custom-translations), in a `dqxclarity/custom-translations/` folder at the root of the ZIP, laid out like the repo:

```
dqxclarity/custom-translations/
├── json/*.json
├── csv/merge.xlsx
├── csv/glossary.csv
└── generate_glossary/ignore.py   (optional)
```

Where dqxclarity gets its custom translations, checked in order:

1. The pack has a `dqxclarity/custom-translations/` folder: only what's in it is used, and nothing is downloaded. A part that's missing is reported in the log and that data is left as it was. Saved machine translations are never removed. `ignore.py` is applied only if the pack includes it.
2. Otherwise, the pack's `custom_translations_url` repo is downloaded.
3. Otherwise, the default dqx-custom-translations repo is downloaded.

Bundled custom translations only change when the pack is rebuilt and updated, while the downloaded ones are the latest every launch.

The **entire ZIP payload** (apart from the `dqxclarity/` folder) is extracted into the game's `Game\mods` folder. There is no per-file manifest — the dragonhook proxy serves every loose file under `Game\mods` in place of the packed DAT archives.

### Building a pack

Use dqxclarity's **Advanced → Build language pack (CLPK)** tool: choose a plain `.zip` of your loose game files, set the author and language (and optionally a download URL and the text settings above), and it stamps the header — computing the `sha` and `builtAt` — into a `.clpk`.

dqxclarity scans the `dqxclarity/language-packs` folder for `*.clpk` (and `*.zip` whose contents are a CLPK).

## Notes

- Keep custom helper scripts in `scripts/`.
- Use `git status` before and after changes.
- `DqxClarity/native/version.dll` is the dragonhook proxy DLL, embedded in the exe and added to / removed from the game folder on demand via the Language tab's Install/Remove support buttons (its presence on disk is what enables language packs in-game).
