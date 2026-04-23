# dqxclarity launcher

the graphical launcher for dqxclarity. it handles first-time setup, settings, database management, and launching the main python application.

## stack

- [.NET 9](https://dotnet.microsoft.com/en-us/download/dotnet/9.0) (windows-only target)
- [Avalonia UI 11.2](https://avaloniaui.net/) - cross-platform XAML UI framework
- [CommunityToolkit.Mvvm](https://learn.microsoft.com/en-us/dotnet/communitytoolkit/mvvm/) - source-generated MVVM helpers
- [Microsoft.Data.Sqlite](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/) - translation cache database access

## building

requires the [.NET 9 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/9.0).

**development build** (fast, unoptimized, run directly):
```
dotnet run
```

**release build** (self-contained single-file exe, what gets shipped):
```
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

output lands at `bin/Release/net9.0-windows/win-x64/publish/dqxclarity.exe`.

## project structure

```
launcher/
├── Assets/          # embedded resources (icons, images)
├── Models/          # plain data types
├── Services/        # business logic (setup, process, config, patching, database)
├── Styles/          # global AXAML styles and themes
├── ViewModels/      # MVVM view models
└── Views/           # AXAML views and code-behind
```

## notes

- uses software rendering (`Win32RenderingMode.Software`) to avoid DirectComposition issues under wine/proton
- single-instance enforced via a named mutex; a second launch brings the existing window to the front
- the launcher expects to find the dqxclarity python environment at `./venv/Scripts/python.exe` relative to the exe

## sendchat tab

the sendchat tab writes japanese text directly into dqx's chat input buffer by walking a pointer chain in `DQXGame.exe`, then firing right-arrow keystrokes so the game's cursor advances past each character as it lands.

### updating the pointer / offsets

when a game patch moves the chat buffer, the pointer chain breaks. the constants live in a single place:

`Services/Send2ChatMemoryService.cs`:

```csharp
private const string   ModuleName   = "DQXGame.exe";
private const uint     BaseOffset   = 0x01C8AA3C;
private static readonly uint[] PointerChain = [0x8, 0x94, 0x4, 0x4, 0x98, 0x2DC, 0x0];
```

resolution walks like this:

1. start at `DQXGame.exe + BaseOffset` (absolute address)
2. read a 4-byte pointer at that address
3. add the next offset from `PointerChain`, repeat until the chain is exhausted
4. the final address is the first byte of the chat input buffer

to rediscover the chain after a patch, use cheat engine (or equivalent) against `DQXGame.exe` (32-bit process):

1. open the chat input field in-game and type a known string (e.g. `あいうえお`)
2. scan for the utf-8 bytes of that string - `E3 81 82 E3 81 84 E3 81 86 E3 81 88 E3 81 8A`
3. type something different, scan the previous results for the new bytes; repeat until one address remains
4. right-click → "find what accesses this address" - you'll get a base pointer and an offset
5. follow the access pointer back through several iterations, recording each offset along the way, until you reach a static address (green in cheat engine) inside `DQXGame.exe`
6. the static offset (minus the module base) becomes `BaseOffset`; the chain of offsets you walked back becomes `PointerChain` (in order from static toward the buffer)

update the three constants and rebuild. everything else - the write loop, arrow-key nudging, elevation check - stays the same.

### adding new quest text to the dropdown

quest strings live in `Services/Send2ChatStrings.cs`. the `Quests` dictionary drives the dropdown; each entry is `{ "dropdown label (english)", "japanese text to send" }`.

to add an entry:

1. open `Services/Send2ChatStrings.cs`
2. add a new line inside the `Quests` dictionary:
   ```csharp
   { "Q999: My New Quest", "ここに日本語を入れる" },
   ```
3. rebuild

rules of thumb:
- keep the key short - it shows in the combobox and gets trimmed with `…` if longer than ~300 px
- the japanese value is sent verbatim; max 20 characters (enforced at write time)
- entries render in insertion order, so group related quests together
- the `CommonPhrases` dictionary directly below `Quests` drives the grid of one-tap buttons - same format, same rules
