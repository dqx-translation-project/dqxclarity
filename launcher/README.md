# dqxclarity launcher

__Yes, this launcher was written with AI. Deal with it.__

a [tauri v2](https://tauri.app/) + [svelte 5](https://svelte.dev/) desktop app. it handles first-time setup, configuration, running dqxclarity, and updates — all in one window.

## what it does

- **first-time setup** — detects whether python 3.11 (32-bit) and the venv are installed. if not, walks the user through installing python and building the venv automatically.
- **settings** — reads and writes `user_settings.ini`. covers translation services (deepl, google translate, community api), game directory, player name overrides, patching options, and ui theme.
- **run** — launches dqxclarity's python process and streams stdout/stderr into a log view in real time. blocks window close while the process is running.
- **database** — browse and delete rows from `clarity_dialog.db`. includes a purge button that wipes all dialog cache entries.
- **updates** — checks github on startup. if a newer release exists, shows an "update now" button with a rendered changelog. clicking it downloads and runs `updater.py`, then exits the launcher so the updater can replace files freely.

## prerequisites

| tool | version |
|------|---------|
| [rust](https://rustup.rs/) | stable (latest) |
| [node.js](https://nodejs.org/) | 20+ |
| npm | bundled with node |
| [microsoft webview2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) | pre-installed on windows 10/11 |

> webview2 is already present on most windows 10 (2019+) and all windows 11 machines. if it's missing, the tauri installer prompts the user to install it.

## dev setup

```sh
cd launcher
npm install
npm run dev
```

`npm run dev` starts the vite dev server and opens the tauri window with hot-reload. changes to `.svelte` files reflect immediately; rust changes require a full restart.

## build

```sh
cd launcher
npm install
npx tauri build --no-bundle
```

the compiled exe lands at `src-tauri/target/release/dqxclarity.exe`. `--no-bundle` skips the msi/nsis installer — the exe is distributed inside the dqxclarity zip instead.

## project layout

```
launcher/
├── src/
│   ├── routes/
│   │   └── +page.svelte       # root page: setup → settings ↔ log view
│   └── lib/
│       ├── Setup.svelte        # first-time setup wizard
│       ├── Settings.svelte     # main settings ui (tabs: general, database, name overrides)
│       ├── Log.svelte          # python process log viewer
│       └── themes.js           # css variable theme definitions
├── src-tauri/
│   ├── src/
│   │   ├── lib.rs              # tauri builder: plugin registration, command handler list
│   │   └── commands/
│   │       ├── config.rs       # load/save user_settings.ini, game dir, theme
│   │       ├── database.rs     # read/delete/purge clarity_dialog.db
│   │       ├── environment.rs  # setup wizard: python install, venv creation
│   │       ├── patch.rs        # game file patching helpers
│   │       ├── process.rs      # launch/stop python process, stream log lines
│   │       ├── update.rs       # github update check, run updater.py
│   │       └── validate.rs     # deepl / google translate key validation
│   └── tauri.conf.json         # app metadata, window config, security policy
├── package.json
└── svelte.config.js
```

## ci/cd

the `.github/workflows/_compile_launcher.yml` reusable workflow builds the exe on `windows-latest`:

1. sets up node 20 and rust stable
2. caches rust build artifacts via `Swatinem/rust-cache`
3. runs `npm install` and `npx tauri build --no-bundle`
4. uploads `dqxclarity.exe` as a build artifact

`build-release.yml` calls this workflow, then packages the exe into the release zip alongside the python app.
