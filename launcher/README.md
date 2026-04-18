# dqxclarity launcher

the graphical launcher for dqxclarity. it handles first-time setup, settings, database management, and launching the main python application.

## stack

- [.NET 9](https://dotnet.microsoft.com/en-us/download/dotnet/9.0) (windows-only target)
- [Avalonia UI 11.2](https://avaloniaui.net/) — cross-platform XAML UI framework
- [CommunityToolkit.Mvvm](https://learn.microsoft.com/en-us/dotnet/communitytoolkit/mvvm/) — source-generated MVVM helpers
- [Microsoft.Data.Sqlite](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/) — translation cache database access

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
