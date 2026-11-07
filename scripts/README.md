# DQXClarity local build & language pack guide

This clone is the full upstream Git repository for:

https://github.com/dqx-translation-project/dqxclarity

Use it as the editable source for custom launcher/UI and feature builds.

## Main edit points

- `launcher/Views/*.axaml`: launcher screens and layout.
- `launcher/Styles/*.axaml`: shared colors, button styles, text styles.
- `launcher/Assets/*`: bundled images and icon.
- `launcher/ViewModels/*`: UI state, commands, tab behavior.
- `launcher/Services/*`: setup, patching, launching, updates, database access, direct login.
- `app/main.py`: Python entrypoint started by the launcher.
- `app/common/*`: config, database, translation dispatch, memory helpers.
- `app/hooking/*`: Frida hook activation and hook scripts.
- `app/scans/*`: scanner processes.

## Build the launcher exe

From the repository root:

```powershell
.\scripts\build-launcher.ps1
```

Output:

```text
launcher\bin\Release\net9.0-windows\win-x64\publish\dqxclarity.exe
```

The native `LocaleHook.dll` build needs CMake plus Visual Studio Build Tools with the C++ desktop workload. If that toolchain is missing, UI-only launcher edits can still usually be built with:

```powershell
.\scripts\build-launcher.ps1 -SkipNative
```

## Build a local distributable folder

From the repository root:

```powershell
.\scripts\package-local.ps1
```

Output:

```text
local-build\dqxclarity\
local-build\dqxclarity-mod.zip
```

That folder contains the Python app, config/default files, database, and the rebuilt `dqxclarity.exe`.

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

- `language` is an ISO code (`en`, `fr`, …). The launcher shows its display name (English, French) via `CultureInfo` and uses it as the pack's identity.
- `builtAt` is a Unix timestamp (seconds); shown as the pack's "updated" date.
- `sha` is the SHA-256 of the ZIP payload, verified on download.
- `downloadUrl` (optional) — a self-describing update URL. The official packs omit it; the launcher then uses the catalog's URL for that language to check for updates.

The **entire ZIP payload** is extracted into the game's `Game\mods` folder. There is no per-file manifest — the dragonhook proxy serves every loose file under `Game\mods` in place of the packed DAT archives.

### Building a pack

Use the launcher's **Advanced → Build language pack (CLPK)** tool: choose a plain `.zip` of your loose game files, set the author and language (and an optional download URL), and it stamps the header — computing the `sha` and `builtAt` — into a `.clpk`.

The launcher scans the `dqxclarity/language-packs` folder for `*.clpk` (and `*.zip` whose contents are a CLPK).

## Notes

- Keep custom helper scripts in `scripts/`.
- Use `git status` before and after changes.
- The launcher is C#/.NET 9 Avalonia; the in-game engine is Python plus Frida hooks.
- The launcher expects the Python app files near the exe in the final packaged folder.
- `launcher/native/version.dll` is the dragonhook proxy DLL, embedded in the launcher and added to / removed from the game folder on demand via the Language tab's Install/Remove support buttons (its presence on disk is what enables language packs in-game).
