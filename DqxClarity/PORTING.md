# porting log

tracks the python → c# port. plan lives at `C:\Users\joey\.claude2\plans\write-me-a-plan-shimmying-haven.md`. all phases now complete; this file is the historical record + smoke-test instructions for the cutover.

## phase a — c# foundations (completed)

- `Packets/PacketBuffer.cs` — port of `app/hooking/hooks/packets/buffer.py`. `PacketReader` is a `ref struct` over `ReadOnlySpan<byte>`; `PacketWriter` is a growable list. cstring read/write semantics match python (null terminator written on write, consumed on read).
- `Data/ClarityDb.cs` + embedded `Data/schema.sql` — port of `app/common/db_ops.py` with parameterised queries. glossary loader preserves the longest-first sort. `GetPlayerNames()` added.
- existing `Services/ConfigService.cs` already had the `translate_service` migration; no rewrite needed.

## phase b — packetwarden.dll (completed)

- `native/PacketWarden.cpp` — native source. signature-scans for `ParseNetworkPacket` (signature from the deleted python `packet_warden.ts`), installs an inline 5-byte jmp hook with a trampoline (no minhook dep needed because the prolog is exactly 5 bytes of clean instructions). filters by type (data) + size_id + a 30-entry `KNOWN_PACKETS` table. blocking named-pipe ipc to the c# host.
- `Hooking/PacketPipe.cs` — named-pipe server, binary length-prefixed protocol, resilient re-accept.
- `Services/PacketWardenService.cs` — extract embedded dll, inject via wow64 module enumeration + `LoadLibraryW` (mirrors the existing `LocaleEmulatorService` pattern).
- `Hooking/ClarityRuntime.cs` — top-of-stack: owns db + glossary + translator + dispatcher + hook service. `Start()` / `InjectInto(hProcess)` / `Stop()`.
- `native/CMakeLists.txt` extended; `native/build.ps1` updated; `Taskfile.yml` `task native` lists both dlls; csproj embeds both.

## phase c — translation pipeline (completed)

- `Translation/Translator.cs` — full port of `translate.py.Translator.translate` (13 stages: br→fullwidth-space, alignment strip, ellipsis collapse, oddity strip, period folding, leading-fullwidth-space strip, honorific strip after name tags, color-tag protect, placeholder swap, glossary, split on non-`%&` tags, backend translate, post-sanitize + normalize-nfkd + wrap + swap-back + br-inject + voice-tag rule with Asfeld `IEV_GS` exception).
- `Translation/GlossaryCache.cs`, `Translation/PlaceholderTags.cs` (full 40-entry forward / multi-length-variant backward tables), `Translation/TextWrapping.cs` (Fill + InjectBrEvery3Lines), `Translation/QuestRewardFormatter.cs`, `Translation/IRomanizer.cs`.
- `Translation/Backends/`:
  - `EchoBackend.cs` (deterministic stub for golden corpus)
  - `GoogleFreeBackend.cs` (mobile scrape, no key)
  - `DeepLBackend.cs` (direct HttpClient against `/v2/translate` with the full custom-instructions array)
  - `GoogleBackend.cs` (direct HttpClient against translate v2 REST; no Google SDK)
  - `GoogleTranslatePaBackend.cs` (translate_a/single, no key)
  - `ChatGPTBackend.cs` (OpenAI chat/completions, system prompt copied verbatim from python)
  - `OllamaBackend.cs` (/api/generate against local instance)
  - `YandexBackend.cs` (unofficial android-app endpoint with ucid)
  - `LibreTranslateBackend.cs` (libretranslate.com or self-hosted)
  - `BackendFactory.cs` — switch on `TranslationConfig.TranslateService`.

## phase d — packet types (completed, 18 of 20)

`Packets/IPacket.cs`, `Packets/GamePacket.cs`, `Packets/DataPacketRouter.cs` (delegate-based dispatch), and:

- `NpcDialoguePacket.cs` — bad-strings → cache → translate → crc recompute (System.IO.Hashing.Crc32)
- `WalkthroughPacket.cs` — 276-byte fixed-buffer text
- `StorySoFarTextPacket.cs` — 517-byte text slot
- `QuestPacket.cs` — 5 fixed-buffer fields
- `ServerListPacket.cs` — static byte-level table (~75 server names)
- `ConciergePacket.cs`, `MyTownAmenityPacket.cs` — m00 lookup → romanise fallback
- `MasterQuestPacket.cs` — null-split string list + `custom_master_quests` lookup
- `CommWindowListPacket.cs`, `PartyListPacket.cs` — player names at fixed offsets
- `EntityPacket.cs` — single class for all 5 entity sub-types
- `PartyListVariants.cs` — variants 2/3/4 with shared length-prefix helper
- `SupportPartyListPacket.cs` — variable-count member list
- `MemoryListMainPacket.cs`, `MemoryListChaptersPacket.cs`, `MemoryListSubChaptersPacket.cs` — quests m00 lookup

intentionally not mapped (python ships hardcoded placeholders that would corrupt packets): `team_quest` (0x3d 0x16b6), `weekly_request` (0x46 0x6bb8). add later when real lookup logic exists.

## phase e — side features (completed)

- `native/wanakana/` rust cdylib + `Translation/Romanizer.cs` p/invoke wrapper. `task wanakana` builds it; csproj embeds + extracts; `NativeLibrary.SetDllImportResolver` finds it at runtime.
- `Updates/TranslationConstants.cs` + `Updates/TranslationUpdater.cs` — port of `update.py.download_custom_files`. github fetch → zip → per-entry routing (json → m00_strings, merge.xlsx via ClosedXML → fixed_dialog_template/walkthrough/quests/story_so_far_template, glossary.csv → glossary, ignore.py → delete filter). parameterised inserts in per-source transactions.
- `Updates/CommunityApi.cs` — port of `__send_string_to_community_api`. `<pnplacehold>` / `<snplacehold>` substitution so the api never sees real player/sibling names.
- `Translation/QuestRewardFormatter.cs` — port of `clean_up_and_return_items`. quest reward lines with item lookup, qty rules, 31-byte slot padding, Experience Points fallback.

## phase f — cutover (completed)

destructive deletes:
- `app/` entire python tree (gone)
- `pyproject.toml` (gone)
- `package.json`, `package-lock.json`, `node_modules/` (gone — used by the deleted typescript frida scripts)
- `.ruff_cache/` (gone)
- `launcher/Services/ProcessService.cs` (python subprocess driver)
- `launcher/Services/SetupService.cs` (python venv installer)
- `launcher/Models/SetupException.cs`, `SetupStep.cs`
- `launcher/ViewModels/SetupViewModel.cs`
- `launcher/Views/SetupView.axaml(.cs)`
- `launcher/Views/UacDialog.axaml(.cs)` (only used during python install elevation)
- `Translation/StepStatusToBrushConverter` (dead converter)
- `Models/LauncherConfig.UseNativeTranslation` (no longer a flag — it's the only mode)

c# rewires:
- `App.axaml.cs` — no longer constructs `SetupService` / `ProcessService`. extracts both `LocaleHook.dll` and `PacketWarden.dll` at startup.
- `MainViewModel.cs` — owns a lazy `ClarityRuntime`. autorun starts it directly; `OnRunRequested` starts it and surfaces a status line. `StopRuntime()` disposes on user stop.
- `LogViewModel.cs` — no longer dependent on `ProcessService`. exposes `AppendLine(text, level)` for runtime status; emits `StopRequested` on user stop. `TryClose()` always returns true (no external process to gate on).
- `MainWindow.axaml.cs` — drops `SetupView` field, `ShowUacAsync`, and the setup-completion welcome trigger. default view switched from `"setup"` to `"settings"`. first-launch welcome now fires on entry to settings.
- `SettingsViewModel.cs` — `PostInjectCallback` property is set by `MainViewModel.EnsureNativeRuntime()` and is forwarded to both `GameLaunchService.Launch(...)` direct-login sites.
- `GameLaunchService.cs` + `LocaleEmulatorService.cs` — both gained an optional `Action<IntPtr>? postInject` parameter that runs inside the `CreateProcessW` finally block (additive only).
- `pre-commit-config.yaml` — dropped python-only hooks (pyupgrade, ruff, debug-statements, check-docstring-first, check-ast). kept generic hooks (eof, line-endings, secrets).
- `version.update` bumped 5.17.0 → 6.0.0 (breaking: no longer python).
- `README.md` short note that this is now c#.
- `Taskfile.yml` — `task native` builds both dlls, `task wanakana` builds the rust cdylib, `task publish` produces `--self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true`.

deferred future cleanup (not blocking, all green):
- the 7 jp→en translation backends could share a small helper for `IDisposable HttpClient` lifetime + json error handling — currently each repeats the same try/catch shape.
- `clarity_dialog.db`, `user_settings.ini`, `misc_files/` stay because they hold user data.
- `RELEASES.md` will want a 6.0.0 entry on next release.
- ui surfacing for `nameplates`, `community logging`, `debug logging` checkboxes still wired through; they just need to map to runtime knobs instead of the deleted python args.

## how to smoke-test the cutover

1. install msvc build tools (existing dep) + rustup with `x86_64-pc-windows-msvc` target (`rustup target add x86_64-pc-windows-msvc`).
2. `cd launcher && task native && task wanakana` — produces `native/LocaleHook.dll`, `native/PacketWarden.dll`, `native/wanakana.dll`.
3. `task publish` — single-file self-contained exe under `bin/Release/net9.0-windows/win-x64/publish/`.
4. run on a clean win11 vm with no .net runtime installed; confirm it launches.
5. log into dqx through the launcher (direct-login flow). confirm:
   - `LocaleHook.dll` injects (japanese title bar / no mojibake — existing behavior)
   - `PacketWarden.dll` injects (debug log at `logs/packetwarden.log` shows "hook installed")
   - named pipe `\\.\pipe\dqxclarity` connects (log file shows "pipe connected")
6. walk to an npc with japanese dialogue; confirm translation appears (using the configured backend).
7. open story-so-far, a quest, a memory chapter; confirm those translate too.
8. sit in a busy zone for 10 minutes; no game disconnects, no perceptible lag.

if anything in steps 5-8 fails: the `app/` directory is gone but recoverable via `git checkout` for a specific path or `git revert` on the cutover commit. nothing on disk in `misc_files/`, `clarity_dialog.db`, or `user_settings.ini` has been touched.

## post-cutover work

### native PacketWarden rewrite (parser resolver + small LDE)

motivation: the original 27-byte prolog signature `55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 83 7D ?? ?? 53 8B 5D ?? 56 8B F1` was tied to a single compiler output of the parser. when dqx is rebuilt and msvc rearranges the prolog, the signature breaks and the dll silently falls back to passthrough (`logs/packetwarden.log` shows `signature not found — passthrough`).

replaced with a body-fingerprint resolver (port of `C:\Users\joey\Desktop\test\sleep_test.js`):

1. scan the main module for every `call dword ptr [reg+0x5C]` and `call dword ptr [reg+0x64]`. those are the two distinctive virtual-call sites the parser uses against its VCE base-class vtable (ProcessPayload slot 23 + ProcessAck slot 25). encoded as `FF /2 [reg+disp8]` so we scan for `FF <50|51|52|53|55|56|57> <5C|64>`.
2. find pairs of (5C call, 64 call) within 0x300 bytes of each other — likely the same function body.
3. for each candidate, scan ±0x200 bytes around the pair for `push 0x16` and `push 0x1B` (log codes 22 and 27 — the parser's per-case branch markers). both must be present.
4. walk back from the earliest body marker, looking for a `CC` padding byte followed by a recognised MSVC prologue (`55 8B`, `8B FF` hotpatch, `53/56/57`, `83 EC`, `81 EC`). that's the function start.

this should survive any recompile that doesn't restructure the VCE base class itself. if it stops working, the table of vtable slot offsets / log codes is what would need to change, not the resolver shape.

prologue trampoline: because the resolver no longer guarantees a specific 5-byte prologue shape, the inline jmp installer can't blindly copy 5 bytes. added a small x86 length-disassembler (`InstrLen` + `ModRmSize` in `PacketWarden.cpp`) that recognises the prologue-style opcodes we expect — push/pop, mov via modrm, sub esp imm8/imm32, etc. — and copies whole instructions until the trampoline has ≥ 5 bytes of clean instruction boundaries. unknown opcodes log the first 8 bytes so the table can be extended.

parser-side filter changes in `H_ParseNetworkPacket`:
- accept both type 0 and type 4 data packets (per `sleep_test.js`); ping(1)/pong(2)/ackn(3) still pass through
- payload offset now `(byte0 & 3) + 2` (was a 4-entry lookup table `[2,3,5,5]` indexed by `byte0 & 0x0F`). new mapping is ll=0→2, ll=1→3, ll=2→4, ll=3→5
- `ComputeOriginalSize` matches: ll=2 reads a 3-byte u24 size (was incorrectly reading 4 bytes); ll=3 reads u32 and accounts for 5 header bytes (was 4)

### c# native log surface (`Hooking/NativeLogTail.cs`)

PacketWarden writes its progress to `<exe-dir>/logs/packetwarden.log` (scan counts, verified candidate count, parser address/RVA, hook-install confirmation, pipe-connect, prologue byte count). the user couldn't see any of that from the launcher UI.

added `NativeLogTail`: starts at end-of-file (no replay of past sessions), polls every 250ms for new bytes, splits on newlines, strips the leading `YYYY-MM-DD HH:MM:SS ` timestamp, and pumps each line through a callback as `[hook] <line>`. polled rather than `FileSystemWatcher` because the dll opens/closes the file on each line so `FileSystemWatcher.Changed` is unreliable.

started by `ClarityRuntime.StartWatchingForGame()` so it lifecycles with the runtime; stopped on dispose.

### game-exit detection

motivation: closing dqx left the runtime running and the watcher loop polling forever.

`ClarityRuntime` now exposes a `GameExited` event. the game-process watcher loop tracks `_lastInjectedPid` post-injection; on each tick, if that pid is no longer present in `Process.GetProcessesByName("DQXGame")`, it logs the exit, fires `GameExited`, and returns (stops watching).

`MainViewModel.EnsureNativeRuntime` hooks the event to run the same teardown as the Stop button: `StopRuntime()` (disposes runtime, closes pipe + log tail + watcher) then `SwitchTo("settings")`. equivalent to pressing Stop manually.
