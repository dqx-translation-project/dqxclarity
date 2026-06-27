# DQXClarity local modification guide

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

## Build the modified launcher exe

From the repository root:

```powershell
.\local-tools\build-launcher.ps1
```

Output:

```text
launcher\bin\Release\net9.0-windows\win-x64\publish\dqxclarity.exe
```

The native `LocaleHook.dll` build needs CMake plus Visual Studio Build Tools with the C++ desktop workload. If that toolchain is missing, UI-only launcher edits can still usually be built with:

```powershell
.\local-tools\build-launcher.ps1 -SkipNative
```

## Build a local distributable folder

From the repository root:

```powershell
.\local-tools\package-local.ps1
```

Output:

```text
local-build\dqxclarity\
local-build\dqxclarity-mod.zip
```

That folder contains the Python app, config/default files, database, and the rebuilt `dqxclarity.exe`.

## Mod zip manifest

Every mod zip scanned by the Mods tab must contain a root-level `mod.jsons`.

Example:

```json
{
  "name": "Example Mod",
  "type": "Translation",
  "version": "1.0.0",
  "author": "Your name",
  "description": "Short description shown only as metadata for now.",
  "homepage": "https://example.com",
  "download_url": "https://example.com/releases/ExampleMod.zip",
  "requires": [],
  "game_mods": [
    "ExampleMod"
  ]
}
```

`game_mods` lists the zip folders or files that should be extracted into the game's `Game\mods` folder. For the example above, the zip should contain:

```text
mod.jsons
ExampleMod\...
```

`download_url` must be a stable direct URL to a zip containing its own `mod.jsons`. The launcher compares the remote manifest version with the installed version and can replace the local archive.

## Notes

- Keep custom helper scripts in `local-tools/` so upstream code remains easy to diff.
- Use `git status` before and after changes.
- The launcher is C#/.NET 9 Avalonia; the in-game engine is Python plus Frida hooks.
- The launcher expects the Python app files near the exe in the final packaged folder.
- `launcher/native/version.dll` is embedded in the launcher and installed in the game only while mod support is running.
