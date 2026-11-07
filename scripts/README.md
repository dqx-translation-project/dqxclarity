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

This builds, in order: `LocaleHook.dll` + `PacketWarden.dll` (CMake + Visual Studio Build Tools, C++ desktop workload), `wanakana.dll` (Rust, `rustup target add x86_64-pc-windows-msvc`), then publishes the exe. The DLLs are embedded into the exe, and a missing DLL is skipped silently by the project file, so a build without them still works but loses that feature (no packet hook, no romaji names).

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
- `downloadUrl` (optional) — a self-describing update URL. The official packs omit it; dqxclarity then uses the catalog's URL for that language to check for updates.

The **entire ZIP payload** is extracted into the game's `Game\mods` folder. There is no per-file manifest — the dragonhook proxy serves every loose file under `Game\mods` in place of the packed DAT archives.

### Building a pack

Use dqxclarity's **Advanced → Build language pack (CLPK)** tool: choose a plain `.zip` of your loose game files, set the author and language (and an optional download URL), and it stamps the header — computing the `sha` and `builtAt` — into a `.clpk`.

dqxclarity scans the `dqxclarity/language-packs` folder for `*.clpk` (and `*.zip` whose contents are a CLPK).

## Notes

- Keep custom helper scripts in `scripts/`.
- Use `git status` before and after changes.
- `DqxClarity/native/version.dll` is the dragonhook proxy DLL, embedded in the exe and added to / removed from the game folder on demand via the Language tab's Install/Remove support buttons (its presence on disk is what enables language packs in-game).
