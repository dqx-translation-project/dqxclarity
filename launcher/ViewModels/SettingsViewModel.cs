using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text.Encodings.Web;
using System.Text.Json;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DqxClarity.Launcher.Models;
using DqxClarity.Launcher.Services;
using DqxClarity.Launcher.Services.Auth;

namespace DqxClarity.Launcher.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly ConfigService   _cfg;
    private readonly PatchService    _patch;
    private readonly DatabaseService _db;
    private readonly ValidateService _validate;
    private readonly LanguagePackService _languagePacks;
    private readonly string          _saveFolderPath;
    private UpdateService?           _updateSvc;
    public Text2ClipboardViewModel Text2Clipboard { get; }

    public event Action<List<string>>? RunRequested; // args list
    public event Action<string>? OpenUrl;
    public event Func<string, string, Task>? ShowInfoRequested;
    public event Func<string, string, Task<bool>>? ShowConfirmRequested;

    // ── Launcher settings ────────────────────────────────────────────────────
    [ObservableProperty] private bool _nameplates;
    [ObservableProperty] private bool _debugLogging;
    [ObservableProperty] private bool _communityLogging;

    // ── Language Packs ────────────────────────────────────────────────────
    [ObservableProperty] private bool   _languagePackSupport;
    [ObservableProperty] private bool   _languagePacksLoading;
    [ObservableProperty] private string _languagePackStatus = "";
    [ObservableProperty] private bool   _languagePackStatusIsError;
    public ObservableCollection<LanguagePack> LanguagePacks { get; } = [];
    public ObservableCollection<LanguagePackCatalogEntry> AvailablePacks { get; } = [];
    private readonly HashSet<string> _savedActiveLanguagePacks = new(StringComparer.OrdinalIgnoreCase);
    private bool _languagePacksScanned;
    private bool _languagePackFirstRunChecked;

    /// <summary>Invoked to let the view show a file picker; returns the chosen .zip path or null.</summary>
    public event Func<Task<string?>>? PickZipFileRequested;

    /// <summary>Invoked to let the view show a save-file picker for a .clpk; returns the chosen path or null.</summary>
    public event Func<string, Task<string?>>? SaveClpkFileRequested;

    // ── Build language pack (CLPK) tool ───────────────────────────────────
    [ObservableProperty] private string _clpkInputZipPath = "";
    [ObservableProperty] private string _clpkName = "";
    [ObservableProperty] private string _clpkAuthor = "";
    [ObservableProperty] private string _clpkLanguage = "en";
    [ObservableProperty] private string _clpkDownloadUrl = "";
    [ObservableProperty] private string _clpkBuildStatus = "";
    [ObservableProperty] private bool   _clpkBuildStatusIsError;

    private void SetClpkBuildStatus(string message, bool isError = false)
    {
        ClpkBuildStatus = message;
        ClpkBuildStatusIsError = isError;
    }

    [RelayCommand]
    private async Task PickClpkInput()
    {
        if (PickZipFileRequested == null) return;
        var path = await PickZipFileRequested.Invoke();
        if (string.IsNullOrWhiteSpace(path)) return;
        ClpkInputZipPath = path;
    }

    [RelayCommand]
    private async Task BuildClpk()
    {
        if (string.IsNullOrWhiteSpace(ClpkInputZipPath))
        {
            SetClpkBuildStatus("Choose an input .zip first.", true);
            return;
        }
        if (SaveClpkFileRequested == null) return;

        try
        {
            var suggested = Path.GetFileNameWithoutExtension(ClpkInputZipPath) + ".clpk";
            var outputPath = await SaveClpkFileRequested.Invoke(suggested);
            if (string.IsNullOrWhiteSpace(outputPath)) return;

            SetClpkBuildStatus("Building...");
            await _languagePacks.BuildClpkAsync(ClpkInputZipPath, outputPath,
                ClpkName, ClpkAuthor, ClpkLanguage, ClpkDownloadUrl);
            SetClpkBuildStatus($"Built {Path.GetFileName(outputPath)}.");
        }
        catch (Exception ex)
        {
            SetClpkBuildStatus($"Build failed: {ex.Message}", true);
        }
    }

    partial void OnLanguagePackSupportChanged(bool value)
    {
        try { _cfg.SaveLanguagePackSupport(value); } catch { }
        SetLanguagePackStatus(value
            ? "Language pack support enabled. version.dll will be installed when you click Run."
            : "Language pack support disabled. version.dll will be removed when possible.");
        if (!value)
            CleanupLanguagePackRuntime();
    }

    [ObservableProperty] private bool _automaticUpdates;

    partial void OnAutomaticUpdatesChanged(bool value)
    {
        try { _cfg.SaveAutomaticLanguagePackUpdates(value); } catch { }
    }

    /// <summary>
    /// Run on startup (fire-and-forget). When automatic updates are enabled, checks every pack with
    /// a download URL and silently downloads + applies any that changed (sha-verified), re-extracting
    /// active packs into Game\mods. Never throws; offline/placeholder URLs simply no-op.
    /// </summary>
    public async Task RunAutomaticUpdatesIfEnabledAsync()
    {
        if (!AutomaticUpdates) return;

        try
        {
            if (!_languagePacksScanned)
                await ScanLanguagePacks();

            var updatedAnyActive = false;
            foreach (var pack in LanguagePacks.Where(p => p.CanActivate && !string.IsNullOrWhiteSpace(p.DownloadUrl)).ToList())
            {
                try
                {
                    var check = await _languagePacks.CheckForUpdateAsync(pack);
                    if (!check.UpdateAvailable) continue;

                    await _languagePacks.ApplyUpdateAsync(pack, check.DownloadedBytes);
                    if (pack.IsActive) updatedAnyActive = true;
                }
                catch { /* one pack failing must not stop the rest */ }
            }

            // Reflect new versions/metadata in the list.
            await ScanLanguagePacks();

            // Re-extract into Game\mods if an active pack changed and support is on.
            if (updatedAnyActive && LanguagePackSupport && DqxDirValid)
            {
                var activePacks = LanguagePacks.Where(m => m.IsActive && m.CanActivate).ToList();
                if (activePacks.Count > 0)
                {
                    try
                    {
                        var count = await Task.Run(() => _languagePacks.RebuildGameModsFolder(DqxDir, activePacks));
                        SetLanguagePackStatus($"Automatic update applied. Game\\mods rebuilt: {activePacks.Count} pack(s), {count} file(s).");
                    }
                    catch (Exception ex) { SetLanguagePackStatus(ex.Message, true); }
                }
            }
        }
        catch { /* never let startup auto-update throw */ }
    }

    // ── Translation ───────────────────────────────────────────────────────
    public record TranslateServiceOption(string Value, string Display);

    public static IReadOnlyList<TranslateServiceOption> TranslateServiceOptions { get; } =
    [
        // disable translation entirely
        new("none",             "None"),
        // key-based (alphabetical)
        new("chatgpt",          "ChatGPT"),
        new("deepl",            "DeepL"),
        new("google",           "Google Translate"),
        new("libretranslate",   "LibreTranslate"),
        new("ollama",           "Ollama"),
        // free (alphabetical)
        new("googlefree",       "Google Translate Mobile (free)"),
        new("googletranslatepa","Google Translate API (free)"),
        new("yandex",           "Yandex (free)"),
    ];

    [ObservableProperty] private TranslateServiceOption? _selectedTranslateService;
    [ObservableProperty] private string _translateKey      = "";
    [ObservableProperty] private string _chatGptModel     = "gpt-4o-mini";
    [ObservableProperty] private string _ollamaUrl         = "http://localhost:11434";
    [ObservableProperty] private string _ollamaModel       = "llama3";
    [ObservableProperty] private string _libreTranslateUrl = "https://libretranslate.com";

    public bool ShowKeyField =>
        SelectedTranslateService?.Value is "deepl" or "google" or "chatgpt" or "libretranslate";

    public bool ShowOllamaFields =>
        SelectedTranslateService?.Value == "ollama";

    public bool ShowChatGptModel =>
        SelectedTranslateService?.Value == "chatgpt";

    public bool ShowLibreTranslateUrl =>
        SelectedTranslateService?.Value == "libretranslate";

    public bool IsFreeService =>
        SelectedTranslateService?.Value is "googlefree" or "googletranslatepa" or "yandex";

    public bool IsNoneService =>
        SelectedTranslateService?.Value == "none";

    public bool ShowValidateButton =>
        SelectedTranslateService?.Value is "deepl" or "google";

    partial void OnSelectedTranslateServiceChanged(TranslateServiceOption? value)
    {
        OnPropertyChanged(nameof(ShowKeyField));
        OnPropertyChanged(nameof(ShowOllamaFields));
        OnPropertyChanged(nameof(ShowChatGptModel));
        OnPropertyChanged(nameof(ShowLibreTranslateUrl));
        OnPropertyChanged(nameof(IsFreeService));
        OnPropertyChanged(nameof(IsNoneService));
        OnPropertyChanged(nameof(ShowValidateButton));
        OnPropertyChanged(nameof(CanValidate));
    }

    // ── Theme ─────────────────────────────────────────────────────────────
    [ObservableProperty] private string  _selectedTheme = "rosie";
    [ObservableProperty] private Bitmap? _characterImage;

    partial void OnSelectedThemeChanged(string value)
    {
        ThemeService.Apply(value);
        CharacterImage = LoadCharacterImage(value);
        try { _cfg.SaveTheme(value); } catch { }
    }

    private static Bitmap? LoadCharacterImage(string theme)
    {
        try
        {
            var uri = new Uri(ThemeService.GetCharacterImageUri(theme));
            return new Bitmap(AssetLoader.Open(uri));
        }
        catch { return null; }
    }

    // ── Game tab ──────────────────────────────────────────────────────────
    [ObservableProperty] private string _dqxDir = "";
    [ObservableProperty] private bool   _dqxDirValid;
    [ObservableProperty] private string _dqxDirError = "";
    [ObservableProperty] private bool   _simultaneousLaunch;
    [ObservableProperty] private bool   _directLogin;
    [ObservableProperty] private string _gameSubTab = "install";

    partial void OnDqxDirValidChanged(bool value)
    {
        if (!value && GameSubTab == "launch")
            GameSubTab = "install";
    }

    partial void OnSimultaneousLaunchChanged(bool value)
    {
        if (value && DirectLogin) DirectLogin = false;
    }

    partial void OnDirectLoginChanged(bool value)
    {
        if (value && SimultaneousLaunch) SimultaneousLaunch = false;
        try { _cfg.SaveDirectLogin(value); } catch { }
    }

    [RelayCommand]
    private void ActivateGameSubTab(string subTab) => GameSubTab = subTab;

    // ── Accounts ──────────────────────────────────────────────────────────
    private DqxAuthService? _addAccountAuth;

    public ObservableCollection<Models.SavedPlayer> Accounts { get; } = [];
    [ObservableProperty] private Models.SavedPlayer? _selectedAccount;
    [ObservableProperty] private bool   _showAddAccountForm;
    [ObservableProperty] private string _newAccountUsername  = "";
    [ObservableProperty] private string _newAccountPassword  = "";
    [ObservableProperty] private bool   _newAccountNeedsOtp;
    [ObservableProperty] private string _newAccountOtp       = "";
    [ObservableProperty] private bool   _addingAccount;
    [ObservableProperty] private string _addAccountError     = "";

    public event Func<Task<string?>>? ShowOtpDialogRequested;

    public bool CanDeleteSelectedAccount => SelectedAccount != null && !SelectedAccount.IsTrialAccount;

    private async Task LoadTrialAccountAsync(int savedAccountNumber)
    {
        var info = await PlayerListReader.ReadTrialInfoAsync(_saveFolderPath);
        if (info == null) return;

        await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
        {
            var trial = new Models.SavedPlayer { Number = 0, IsTrialAccount = true };
            Accounts.Add(trial);
            if (savedAccountNumber == 0 || SelectedAccount == null)
                SelectedAccount = trial;
        });
    }

    public bool IsTrialAccountSelected => SelectedAccount?.IsTrialAccount == true;

    partial void OnSelectedAccountChanged(Models.SavedPlayer? value)
    {
        try { _cfg.SaveDirectLoginAccountNumber(value?.Number ?? 0); } catch { }
        OnPropertyChanged(nameof(CanDeleteSelectedAccount));
        OnPropertyChanged(nameof(IsTrialAccountSelected));
    }

    [RelayCommand]
    private void ToggleAddAccountForm()
    {
        ShowAddAccountForm = !ShowAddAccountForm;
        NewAccountUsername = "";
        NewAccountPassword = "";
        NewAccountNeedsOtp = false;
        NewAccountOtp      = "";
        AddAccountError    = "";
        _addAccountAuth    = null;
    }

    [RelayCommand]
    private void CancelAddAccount()
    {
        ShowAddAccountForm = false;
        NewAccountUsername = "";
        NewAccountPassword = "";
        NewAccountNeedsOtp = false;
        NewAccountOtp      = "";
        AddAccountError    = "";
        _addAccountAuth    = null;
    }

    [RelayCommand]
    private async Task SubmitNewAccount()
    {
        if (string.IsNullOrWhiteSpace(NewAccountUsername) || string.IsNullOrWhiteSpace(NewAccountPassword))
        {
            AddAccountError = "Username and password are required.";
            return;
        }

        AddAccountError = "";
        AddingAccount   = true;

        _addAccountAuth = new DqxAuthService();
        var r1 = await _addAccountAuth.BeginNewLoginAsync();
        if (r1.Status == AuthStatus.Error)
        {
            AddAccountError = r1.ErrorMessage ?? "Failed to connect to login server.";
            AddingAccount   = false;
            return;
        }

        var r2 = await _addAccountAuth.SubmitCredentialsAsync(NewAccountUsername, NewAccountPassword);

        if (r2.Status == AuthStatus.NeedsOtp)
        {
            NewAccountNeedsOtp = true;
            AddingAccount      = false;
            return;
        }

        FinishAddAccount(r2);
    }

    [RelayCommand]
    private async Task SubmitNewAccountOtp()
    {
        if (_addAccountAuth == null) return;
        AddAccountError = "";
        AddingAccount   = true;
        var r = await _addAccountAuth.SubmitOtpAsync(NewAccountOtp);
        FinishAddAccount(r);
    }

    private void FinishAddAccount(AuthResult result)
    {
        if (result.Status != AuthStatus.Success)
        {
            AddAccountError = result.ErrorMessage ?? "Login failed. Check your credentials.";
            AddingAccount   = false;
            return;
        }

        var nextNumber = _cfg.NextPlayerNumber(Accounts.ToList());
        if (nextNumber == null)
        {
            AddAccountError = "All 4 character slots are already in use.";
            AddingAccount   = false;
            return;
        }

        var player = new Models.SavedPlayer
        {
            Number   = nextNumber.Value,
            Username = NewAccountUsername,
            Password = NewAccountPassword,
        };

        _cfg.SavePlayer(player);

        Accounts.Add(player);
        SelectedAccount    = player;
        ShowAddAccountForm = false;
        NewAccountUsername = "";
        NewAccountPassword = "";
        NewAccountNeedsOtp = false;
        NewAccountOtp      = "";
        AddAccountError    = "";
        AddingAccount      = false;
        _addAccountAuth    = null;
    }

    [RelayCommand]
    private async Task DeleteAccount()
    {
        if (SelectedAccount == null) return;

        if (ShowConfirmRequested != null)
        {
            var confirmed = await ShowConfirmRequested(
                "Remove account",
                $"Remove \"{SelectedAccount.Username}\" from the account list?");
            if (!confirmed) return;
        }

        _cfg.RemovePlayer(SelectedAccount.Number);
        Accounts.Remove(SelectedAccount);
        SelectedAccount = Accounts.FirstOrDefault();
    }

    [ObservableProperty] private bool   _patching;
    [ObservableProperty] private string _patchStatus = "";
    [ObservableProperty] private bool   _patchIsError;
    [ObservableProperty] private long   _patchDownloaded;
    [ObservableProperty] private long   _patchTotal;

    // ── Maintenance ───────────────────────────────────────────────────────
    private readonly MaintenanceService _maintenance;
    [ObservableProperty] private bool             _checkingMaintenance    = true;
    [ObservableProperty] private bool             _refreshOnCooldown;
    [ObservableProperty] private string           _refreshCountdownText   = "";
    [ObservableProperty] private MaintenanceState _serverState            = MaintenanceState.Unknown;
    [ObservableProperty] private string           _serverMessage          = "";

    public bool ServerIsUp      => !CheckingMaintenance && ServerState == MaintenanceState.Up;
    public bool ServerIsDown    => !CheckingMaintenance && ServerState == MaintenanceState.Down;
    public bool ServerIsUnknown => !CheckingMaintenance && ServerState == MaintenanceState.Unknown;

    partial void OnCheckingMaintenanceChanged(bool value)
    {
        OnPropertyChanged(nameof(ServerIsUp));
        OnPropertyChanged(nameof(ServerIsDown));
        OnPropertyChanged(nameof(ServerIsUnknown));
        CheckMaintenanceCommand.NotifyCanExecuteChanged();
    }

    partial void OnRefreshOnCooldownChanged(bool value) =>
        CheckMaintenanceCommand.NotifyCanExecuteChanged();

    partial void OnServerStateChanged(MaintenanceState value)
    {
        OnPropertyChanged(nameof(ServerIsUp));
        OnPropertyChanged(nameof(ServerIsDown));
        OnPropertyChanged(nameof(ServerIsUnknown));
    }

    private bool CanCheckMaintenance() => !CheckingMaintenance && !RefreshOnCooldown;

    private async Task FetchMaintenanceStatus()
    {
        CheckingMaintenance = true;
        var (state, message) = await _maintenance.CheckAsync();
        ServerState         = state;
        ServerMessage       = message ?? "";
        CheckingMaintenance = false;
    }

    private async Task RunRefreshCooldown()
    {
        RefreshOnCooldown = true;
        for (var i = 10; i > 0; i--)
        {
            RefreshCountdownText = $"({i})";
            await Task.Delay(1000);
        }
        RefreshCountdownText = "";
        RefreshOnCooldown    = false;
    }

    [RelayCommand(CanExecute = nameof(CanCheckMaintenance))]
    private async Task CheckMaintenance()
    {
        await FetchMaintenanceStatus();
        _ = RunRefreshCooldown();
    }

    // ── UI state ─────────────────────────────────────────────────────────
    [ObservableProperty] private string _activeTab = "general";
    [ObservableProperty] private string _statusMsg = "";
    [ObservableProperty] private bool   _validating;
    [ObservableProperty] private string _hintText = "";
    [ObservableProperty] private bool   _updaterRunning;
    [ObservableProperty] private bool   _showDbHelp;
    // ── Name overrides ────────────────────────────────────────────────────
    public ObservableCollection<NamePair> PlayerNames { get; } = [];
    public ObservableCollection<NamePair> MytownNames { get; } = [];
    [ObservableProperty] private string _overridesSaveError = "";
    [ObservableProperty] private bool   _overridesSaveSuccess;
    private bool _nameOverridesLoaded;
    private bool _nameOverridesDirty;

    // ── Database ──────────────────────────────────────────────────────────
    [ObservableProperty] private bool   _dbLoading;
    [ObservableProperty] private string _dbError = "";
    [ObservableProperty] private string _dbSelectedTable = "";
    [ObservableProperty] private string _dbRowCount = "";
    [ObservableProperty] private string _dbFilter = "";
    public ObservableCollection<string>  DbTables  { get; } = [];
    public ObservableCollection<string>  DbColumns { get; } = [];

    // Plain lists — no per-item change notifications; the view resets ItemsSource in bulk.
    private List<DbRow> _dbRows         = [];
    private List<DbRow> _dbFilteredRows = [];
    public  IReadOnlyList<DbRow> DbRows         => _dbRows;
    public  IReadOnlyList<DbRow> DbFilteredRows => _dbFilteredRows;

    [ObservableProperty] private UpdateInfo? _updateInfo;
    public string Version { get; private set; } = "???";

    partial void OnUpdateInfoChanged(UpdateInfo? value)
    {
        OnPropertyChanged(nameof(UpdateBarText));
        OnPropertyChanged(nameof(UpdateButtonText));
    }

    partial void OnHintTextChanged(string value) =>
        OnPropertyChanged(nameof(UpdateBarText));

    public string UpdateBarText => HintText;

    /// <summary>
    /// Label for the update button, e.g. "Update to 1.2.3".
    /// </summary>
    public string UpdateButtonText =>
        UpdateInfo != null ? $"Update to {UpdateInfo.Version}" : "";

    public void SetUpdateInfo(UpdateInfo info) => UpdateInfo = info;

    public SettingsViewModel(
        AppConfig config,
        string version,
        UpdateInfo? updateInfo,
        Text2ClipboardViewModel text2Clipboard,
        ConfigService cfg,
        PatchService patch,
        DatabaseService db,
        ValidateService validate,
        MaintenanceService maintenance,
        LanguagePackService languagePacks)
    {
        Text2Clipboard    = text2Clipboard;
        _cfg         = cfg;
        _patch       = patch;
        _db          = db;
        _validate    = validate;
        _maintenance = maintenance;
        _languagePacks = languagePacks;

        Version    = version;
        _updateInfo = updateInfo;

        _nameplates        = config.Launcher.Nameplates;
        _debugLogging      = config.Launcher.DebugLogging;
        _communityLogging  = config.Launcher.CommunityLogging;
        _selectedTheme     = config.Launcher.Theme;
        _characterImage    = LoadCharacterImage(_selectedTheme);
        _languagePackSupport = config.Launcher.LanguagePackSupport;
        _automaticUpdates    = config.Launcher.AutomaticLanguagePackUpdates;
        foreach (var fileName in config.Launcher.ActiveLanguagePacks)
            _savedActiveLanguagePacks.Add(fileName);
        try { _languagePacks.EnsureSourceLanguagePacksFolder(); } catch { }

        var savedService = config.Translation.TranslateService;
        _selectedTranslateService = TranslateServiceOptions.FirstOrDefault(o => o.Value == savedService)
                                    ?? TranslateServiceOptions.First(o => o.Value == "googlefree");
        _translateKey       = config.Translation.TranslateKey;
        _chatGptModel      = config.Translation.ChatGptModel;
        _ollamaUrl          = config.Translation.OllamaUrl;
        _ollamaModel        = config.Translation.OllamaModel;
        _libreTranslateUrl  = config.Translation.LibreTranslateUrl;
        _dqxDir           = config.Game.InstallDirectory;
        _saveFolderPath   = config.Game.SaveFolderPath;
        _simultaneousLaunch = config.Launcher.SimultaneousLaunch;
        _directLogin        = config.Launcher.DirectLogin;

        foreach (var p in config.Players)
            Accounts.Add(p);
        _selectedAccount = Accounts.FirstOrDefault(a => a.Number == config.Launcher.DirectLoginAccountNumber)
                           ?? Accounts.FirstOrDefault();

        _ = LoadTrialAccountAsync(config.Launcher.DirectLoginAccountNumber);

        // Resolve + validate the game directory on launch so the Game tab is usable
        // immediately. If the saved path is empty, fall back to the default install
        // location. If nothing resolves, surface an error instead of silently hiding
        // the tab contents.
        if (string.IsNullOrEmpty(_dqxDir) && cfg.ValidateDqxDir(ConfigService.DefaultDqxDir, out _))
        {
            _dqxDir = ConfigService.DefaultDqxDir;
            try { cfg.SaveGameDir(_dqxDir); } catch { }
        }

        if (!string.IsNullOrEmpty(_dqxDir))
        {
            _dqxDirValid = cfg.ValidateDqxDir(_dqxDir, out var dqxErr);
            if (!_dqxDirValid) _dqxDirError = dqxErr;
            else InitializeLanguagePacksFolder();
        }
        else
        {
            _dqxDirError = $"DQX installation not found at the default location ({ConfigService.DefaultDqxDir}). Browse to your DQX installation folder to continue.";
            SetLanguagePackStatus("dqxclarity\\language-packs is ready. Set a valid DQX folder path before activating language packs.");
        }

        _ = FetchMaintenanceStatus();

        _patch.Progress += (downloaded, total) =>
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                PatchDownloaded = downloaded;
                PatchTotal = total;
            });

        static void WirePair(NamePair p, Action setDirty) =>
            p.PropertyChanged += (_, _) => setDirty();

        PlayerNames.CollectionChanged += (_, e) =>
        {
            _nameOverridesDirty = true;
            if (e.NewItems != null)
                foreach (NamePair p in e.NewItems) WirePair(p, () => _nameOverridesDirty = true);
        };
        MytownNames.CollectionChanged += (_, e) =>
        {
            _nameOverridesDirty = true;
            if (e.NewItems != null)
                foreach (NamePair p in e.NewItems) WirePair(p, () => _nameOverridesDirty = true);
        };
    }

    // ── Tab activation ───────────────────────────────────────────────────

    [RelayCommand]
    private async Task ActivateTab(string tab)
    {
        if (ActiveTab == "nameoverrides" && tab != "nameoverrides" && _nameOverridesDirty)
            await PromptSaveNameOverrides();

        ActiveTab = tab;

        if (tab == "nameoverrides" && !_nameOverridesLoaded)
        {
            _nameOverridesLoaded = true;
            _ = LoadNamePairsAsync();
        }
        else if (tab == "languagepacks")
        {
            await ScanLanguagePacks();
            // Fire-and-forget first-run default English download so it never blocks the UI.
            _ = EnsureDefaultLanguagePackAsync();
            await CheckLanguagePackUpdates();
        }
    }

    private async Task PromptSaveNameOverrides()
    {
        if (ShowConfirmRequested == null) return;
        var save = await ShowConfirmRequested(
            "Unsaved Changes",
            "You have unsaved name override changes. Save them now?");
        if (save) SaveNameOverrides();
    }

    // ── Validation ────────────────────────────────────────────────────────

    partial void OnValidatingChanged(bool value) => OnPropertyChanged(nameof(CanValidate));

    public bool CanValidate =>
        !Validating && (SelectedTranslateService?.Value is "deepl" or "google");

    [RelayCommand]
    private async Task ValidateKey()
    {
        Validating = true;
        StatusMsg = "Validating…";
        try
        {
            var svc = SelectedTranslateService?.Value;
            if (svc == "deepl")
                StatusMsg = await _validate.ValidateDeepLKey(TranslateKey);
            else if (svc == "google")
                StatusMsg = await _validate.ValidateGoogleKey(TranslateKey);
            else
                StatusMsg = "Select DeepL or Google Translate to validate.";
        }
        catch (Exception ex)
        {
            StatusMsg = ex.Message;
        }
        Validating = false;
    }

    // ── Run ───────────────────────────────────────────────────────────────

    [RelayCommand]
    public async Task Run()
    {
        if (_nameOverridesDirty)
            await PromptSaveNameOverrides();

        var svc = SelectedTranslateService?.Value;
        var missing = new List<string>();
        if (svc is "deepl" or "google" or "chatgpt" && string.IsNullOrWhiteSpace(TranslateKey))
            missing.Add(SelectedTranslateService?.Display ?? "Translation service");

        if (missing.Count > 0)
        {
            if (ShowInfoRequested != null)
                await ShowInfoRequested("Missing API Keys",
                    $"The following enabled API services have no key entered:\n\n  • {string.Join("\n  • ", missing)}\n\nEnter the missing key(s) before running.");
            return;
        }

        var launcherCfg = new LauncherConfig
        {
            Nameplates               = Nameplates,
            DebugLogging             = DebugLogging,
            CommunityLogging         = CommunityLogging,
            SimultaneousLaunch       = SimultaneousLaunch,
            DirectLogin              = DirectLogin,
            DirectLoginAccountNumber = SelectedAccount?.Number ?? 0,
            Theme                    = SelectedTheme,
            LanguagePackSupport      = LanguagePackSupport,
            ActiveLanguagePacks      = GetActiveLanguagePackFileNames(),
        };
        var translation = new TranslationConfig
        {
            TranslateService   = svc ?? "",
            TranslateKey       = TranslateKey,
            ChatGptModel       = ChatGptModel,
            OllamaUrl          = OllamaUrl,
            OllamaModel        = OllamaModel,
            LibreTranslateUrl  = LibreTranslateUrl,
        };
        try { _cfg.Save(launcherCfg, translation); } catch { }

        if (DirectLogin)
        {
            if (SelectedAccount == null)
            {
                if (ShowInfoRequested != null)
                    await ShowInfoRequested("No account selected",
                        "Select an account from the Accounts list under Game → Launch before running.");
                return;
            }

            if (SelectedAccount.IsTrialAccount)
            {
                StatusMsg = "Logging in…";
                var trialInfo = await PlayerListReader.ReadTrialInfoAsync(_saveFolderPath);
                if (trialInfo == null)
                {
                    StatusMsg = "";
                    if (ShowInfoRequested != null)
                        await ShowInfoRequested("Login failed", "Easy Play account data not found in player list.");
                    return;
                }

                var trialAuth = new DqxTrialAuthService();
                var tr = await trialAuth.AuthenticateAsync(trialInfo.Id, trialInfo.Token);
                StatusMsg = "";

                if (!tr.Success)
                {
                    if (ShowInfoRequested != null)
                        await ShowInfoRequested("Login failed", tr.ErrorMessage ?? "Trial account login failed.");
                    return;
                }

                if (tr.NewDeviceToken != null)
                    await PlayerListReader.UpdateTrialTokenAsync(tr.NewDeviceToken, _saveFolderPath);

                try
                {
                    if (!PrepareLanguagePackRuntime())
                        return;
                    new GameLaunchService().Launch(DqxDir, tr.SessionId!, 99);
                }
                catch (Exception ex)
                {
                    CleanupLanguagePackRuntime();
                    if (ShowInfoRequested != null)
                        await ShowInfoRequested("Launch failed", ex.Message);
                    return;
                }
            }
            else
            {
                StatusMsg = "Logging in…";
                var auth = new DqxAuthService();
                var r1 = await auth.BeginNewLoginAsync();
                if (r1.Status == AuthStatus.Error)
                {
                    StatusMsg = "";
                    if (ShowInfoRequested != null)
                        await ShowInfoRequested("Login failed", r1.ErrorMessage ?? "Failed to connect to the login server.");
                    return;
                }

                var r2 = await auth.SubmitCredentialsAsync(SelectedAccount.Username, SelectedAccount.Password);

                if (r2.Status == AuthStatus.NeedsOtp)
                {
                    StatusMsg = "";
                    var otp = ShowOtpDialogRequested != null ? await ShowOtpDialogRequested() : null;
                    if (string.IsNullOrEmpty(otp)) return;
                    r2 = await auth.SubmitOtpAsync(otp);
                }

                StatusMsg = "";
                AuthResult finalResult = r2;

                if (finalResult.Status != AuthStatus.Success)
                {
                    if (ShowInfoRequested != null)
                        await ShowInfoRequested("Login failed",
                            finalResult.ErrorMessage ?? "Login failed. Check your username and password.");
                    return;
                }

                try
                {
                    if (!PrepareLanguagePackRuntime())
                        return;
                    var gameLauncher = new GameLaunchService();
                    gameLauncher.Launch(DqxDir, finalResult.SessionId!, SelectedAccount.Number);
                }
                catch (Exception ex)
                {
                    CleanupLanguagePackRuntime();
                    if (ShowInfoRequested != null)
                        await ShowInfoRequested("Launch failed", ex.Message);
                    return;
                }
            }
        }
        else if (SimultaneousLaunch && !string.IsNullOrEmpty(DqxDir))
        {
            if (!PrepareLanguagePackRuntime())
                return;
            try { _cfg.LaunchDqx(DqxDir); }
            catch
            {
                CleanupLanguagePackRuntime();
            }
        }
        else if (!PrepareLanguagePackRuntime())
        {
            return;
        }

        var args = new List<string>();
        if (Nameplates)       args.Add("--nameplates");
        if (DebugLogging)     args.Add("--debug");
        if (CommunityLogging) args.Add("--community-logging");
        if (!string.IsNullOrEmpty(svc) && svc != "none") args.Add("--communication-window");

        RunRequested?.Invoke(args);
        await Task.CompletedTask;
    }

    // ── Name overrides ────────────────────────────────────────────────────

    private NamePair MakePlayerPair(string ja, string en) =>
        new(ja, en, p => PlayerNames.Remove(p));

    private NamePair MakeMytownPair(string ja, string en) =>
        new(ja, en, p => MytownNames.Remove(p));

    private async Task LoadNamePairsAsync()
    {
        var raw = _cfg.ReadNameOverrides();

        JsonDocument? doc = null;
        try { doc = JsonDocument.Parse(raw); }
        catch { }

        if (doc == null)
        {
            if (raw.StartsWith("misc_files/"))
                return; // file doesn't exist yet — empty collections is the right state

            if (ShowConfirmRequested != null)
                await ShowConfirmRequested(
                    "Invalid JSON",
                    "name_overrides.json contains invalid JSON and cannot be loaded.\n\nStart over with a clean, empty format?");
            // Either answer: leave collections empty. User can save to overwrite the broken file.
            return;
        }

        if (doc.RootElement.TryGetProperty("player_names", out var pn))
            foreach (var kv in pn.EnumerateObject())
                PlayerNames.Add(MakePlayerPair(kv.Name, kv.Value.GetString() ?? ""));

        if (doc.RootElement.TryGetProperty("mytown_names", out var mn))
            foreach (var kv in mn.EnumerateObject())
                MytownNames.Add(MakeMytownPair(kv.Name, kv.Value.GetString() ?? ""));

        _nameOverridesDirty = false;
    }

    [RelayCommand]
    private void AddPlayerName() => PlayerNames.Add(MakePlayerPair("", ""));

    [RelayCommand]
    private void AddMytownName() => MytownNames.Add(MakeMytownPair("", ""));

    [RelayCommand]
    private void SaveNameOverrides()
    {
        OverridesSaveError   = "";
        OverridesSaveSuccess = false;

        try
        {
            var playerDict = new Dictionary<string, string>();
            foreach (var p in PlayerNames.Where(p => !string.IsNullOrWhiteSpace(p.Japanese)))
                playerDict[p.Japanese] = p.Preferred;

            var mytownDict = new Dictionary<string, string>();
            foreach (var p in MytownNames.Where(p => !string.IsNullOrWhiteSpace(p.Japanese)))
                mytownDict[p.Japanese] = p.Preferred;

            var json = JsonSerializer.Serialize(
                new { player_names = playerDict, mytown_names = mytownDict },
                new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                });

            _cfg.SaveNameOverrides(json);
            _nameOverridesDirty  = false;
            OverridesSaveSuccess = true;
            _ = Task.Delay(2000).ContinueWith(_ =>
                Avalonia.Threading.Dispatcher.UIThread.Post(() => OverridesSaveSuccess = false));
        }
        catch (Exception ex)
        {
            OverridesSaveError = $"Save failed: {ex.Message}";
        }
    }

    // ── Database ──────────────────────────────────────────────────────────

    [RelayCommand]
    private async Task ReadDatabase()
    {
        DbLoading = true;
        DbError = "";
        DbTables.Clear(); DbColumns.Clear();
        _dbRows = []; _dbFilteredRows = [];
        OnPropertyChanged(nameof(DbFilteredRows));
        DbSelectedTable = "";
        DbRowCount = "";
        try
        {
            var tables = await Task.Run(() => _db.ReadTables());
            foreach (var t in tables) DbTables.Add(t);
        }
        catch (Exception ex) { DbError = ex.Message; }
        DbLoading = false;
    }

    [RelayCommand]
    private async Task LoadDbTable(string? table)
    {
        if (string.IsNullOrEmpty(table)) return;
        DbSelectedTable = table;
        DbFilter = "";
        DbColumns.Clear();
        _dbRows = []; _dbFilteredRows = [];
        OnPropertyChanged(nameof(DbFilteredRows));
        DbRowCount = "";
        DbLoading = true;
        try
        {
            var data = await Task.Run(() => _db.ReadTable(table));
            if (table is "dialog" or "quests" or "story_so_far" or "walkthrough")
            {
                var jaIdx = data.Columns.IndexOf("ja");
                var enIdx = data.Columns.IndexOf("en");
                var keep  = new[] { jaIdx, enIdx }.Where(i => i >= 0).ToList();
                if (keep.Count < data.Columns.Count)
                    data = new DbTableData
                    {
                        Columns = keep.Select(i => data.Columns[i]).ToList(),
                        Rows    = data.Rows.Select(r => new DbRow
                        {
                            RowId  = r.RowId,
                            Values = keep.Select(i => i < r.Values.Count ? r.Values[i] : null).ToList(),
                        }).ToList(),
                    };
            }
            foreach (var c in data.Columns) DbColumns.Add(c);
            _dbRows = data.Rows;                       // bulk assign — no per-row notifications
            DbRowCount = $"{data.Rows.Count:N0} rows read";
            OnPropertyChanged(nameof(DbColumns));      // triggers RebuildDbGrid in code-behind
            ApplyFilter();
        }
        catch (Exception ex) { DbError = ex.Message; }
        DbLoading = false;
    }

    partial void OnDbFilterChanged(string value) => ApplyFilter();

    private void ApplyFilter()
    {
        var f = DbFilter.Trim().ToLowerInvariant();
        _dbFilteredRows = string.IsNullOrEmpty(f)
            ? new List<DbRow>(_dbRows)
            : _dbRows.Where(r => r.Values.Any(v => v?.ToLowerInvariant().Contains(f) == true)).ToList();
        OnPropertyChanged(nameof(DbFilteredRows));     // code-behind resets ItemsSource in bulk
    }

    [RelayCommand]
    private async Task ConfirmDbDelete()
    {
        var ids = new HashSet<long>(_dbRows.Where(r => r.Selected).Select(r => r.RowId));
        try
        {
            await Task.Run(() => _db.DeleteRows(DbSelectedTable, ids));
            _dbRows.RemoveAll(r => ids.Contains(r.RowId));
            DbRowCount = $"{_dbRows.Count:N0} rows read";
            ApplyFilter();                             // rebuilds filtered list and notifies view
        }
        catch (Exception ex) { DbError = ex.Message; }
    }

    [RelayCommand]
    private async Task PurgeDialogCache()
    {
        try
        {
            await Task.Run(() => _db.PurgeDialogCache());
            if (DbSelectedTable == "dialog")
            {
                DbColumns.Clear();
                _dbRows = []; _dbFilteredRows = [];
                OnPropertyChanged(nameof(DbFilteredRows));
                DbSelectedTable = "";
                DbRowCount = "";
            }
        }
        catch (Exception ex) { DbError = ex.Message; }
    }

    // ── Game tab ──────────────────────────────────────────────────────────

    private void SetLanguagePackStatus(string message, bool isError = false)
    {
        LanguagePackStatus = message;
        LanguagePackStatusIsError = isError;
    }

    private void InitializeLanguagePacksFolder()
    {
        if (!DqxDirValid) return;
        try
        {
            _languagePacks.EnsureFolders(DqxDir);
            SetLanguagePackStatus(LanguagePackSupport
                ? "Language pack support enabled. version.dll will be installed when you click Run."
                : "Language pack folders ready.");
        }
        catch (Exception ex)
        {
            SetLanguagePackStatus(ex.Message, true);
        }
    }

    public void CleanupLanguagePackRuntime()
    {
        if (!DqxDirValid) return;

        try
        {
            _languagePacks.CleanupRuntime(DqxDir);
            if (!LanguagePackSupport)
                SetLanguagePackStatus("Language pack support disabled.");
        }
        catch (Exception ex)
        {
            SetLanguagePackStatus($"Could not remove version.dll: {ex.Message}", true);
        }
    }

    private bool PrepareLanguagePackRuntime()
    {
        if (!DqxDirValid)
        {
            if (LanguagePackSupport)
                SetLanguagePackStatus("Set a valid DQX folder path before using language pack support.", true);
            return !LanguagePackSupport;
        }

        try
        {
            _languagePacks.PrepareRuntime(DqxDir, LanguagePackSupport);
            SetLanguagePackStatus(LanguagePackSupport
                ? "Language pack support active for this run."
                : "Language pack support disabled.");
            return true;
        }
        catch (Exception ex)
        {
            SetLanguagePackStatus(ex.Message, true);
            return false;
        }
    }

    [RelayCommand]
    private async Task ScanLanguagePacks()
    {
        LanguagePacksLoading = true;
        try
        {
            var activeFileNames = LanguagePacks
                .Where(m => m.IsActive)
                .Select(m => Path.GetFileName(m.Path))
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            activeFileNames.UnionWith(_savedActiveLanguagePacks);

            var files = await Task.Run(() => _languagePacks.ScanLanguagePacks());
            LanguagePacks.Clear();
            foreach (var file in files)
            {
                file.IsActive = activeFileNames.Contains(Path.GetFileName(file.Path));
                if (file.IsActive && file.CanActivate)
                    file.Status = "Active";
                LanguagePacks.Add(file);
            }
            _languagePacksScanned = true;
            RefreshAvailablePacks();
            SetLanguagePackStatus(files.Count == 0 ? "No .zip language packs found in dqxclarity\\language-packs." : $"{files.Count} .zip language pack(s) found in dqxclarity\\language-packs.");
        }
        catch (Exception ex)
        {
            SetLanguagePackStatus(ex.Message, true);
        }
        LanguagePacksLoading = false;
    }

    [RelayCommand]
    private async Task CheckLanguagePackUpdates()
    {
        LanguagePacksLoading = true;
        try
        {
            var checkable = LanguagePacks.Where(m => m.CanActivate).ToList();
            if (checkable.Count == 0)
            {
                SetLanguagePackStatus("No valid language packs to check.");
                return;
            }

            await _languagePacks.CheckUpdatesAsync(checkable);
            var updates = checkable.Count(m => m.Status.StartsWith("Update available:", StringComparison.OrdinalIgnoreCase));
            SetLanguagePackStatus(updates == 0 ? "No language pack updates found." : $"{updates} language pack update(s) available.");
        }
        catch (Exception ex)
        {
            SetLanguagePackStatus(ex.Message, true);
        }
        finally
        {
            LanguagePacksLoading = false;
        }
    }

    private void RefreshAvailablePacks()
    {
        var notInstalled = LanguagePackCatalog.NotInstalled(LanguagePacks);
        AvailablePacks.Clear();
        foreach (var entry in notInstalled)
            AvailablePacks.Add(entry);
    }

    [RelayCommand]
    private async Task DownloadCatalogPack(LanguagePackCatalogEntry? entry)
    {
        if (entry == null) return;
        LanguagePacksLoading = true;
        try
        {
            SetLanguagePackStatus($"Downloading {entry.Name}...");
            await _languagePacks.DownloadCatalogPackAsync(entry);
        }
        catch (Exception ex)
        {
            SetLanguagePackStatus($"Could not download {entry.Name}: {ex.Message}", true);
            LanguagePacksLoading = false;
            return;
        }
        LanguagePacksLoading = false;

        await ScanLanguagePacks();
        SetLanguagePackStatus($"Downloaded {entry.Name}.");
    }

    [RelayCommand]
    private async Task LoadPackFromDisk()
    {
        if (PickZipFileRequested == null) return;

        var path = await PickZipFileRequested.Invoke();
        if (string.IsNullOrWhiteSpace(path)) return;

        LanguagePacksLoading = true;
        LanguagePack imported;
        try
        {
            imported = await Task.Run(() => _languagePacks.ImportZipFromDisk(path));
        }
        catch (Exception ex)
        {
            SetLanguagePackStatus($"Could not import zip: {ex.Message}", true);
            LanguagePacksLoading = false;
            return;
        }
        LanguagePacksLoading = false;

        await ScanLanguagePacks();
        SetLanguagePackStatus($"Imported {imported.Name}.");
    }

    /// <summary>
    /// On the very first run, attempt to fetch and activate the default English catalog pack.
    /// Never throws to the caller; always marks first-run done afterward so it doesn't retry.
    /// </summary>
    public async Task EnsureDefaultLanguagePackAsync()
    {
        if (_languagePackFirstRunChecked) return;
        _languagePackFirstRunChecked = true;

        try
        {
            if (_cfg.Load().Launcher.LanguagePackFirstRunDone)
                return;

            var defaultEntry = LanguagePackCatalog.Default;
            if (defaultEntry == null)
                return;

            // Make sure we have an up-to-date view of what's already installed.
            if (!_languagePacksScanned)
            {
                try { await ScanLanguagePacks(); } catch { }
            }

            if (LanguagePackCatalog.IsInstalled(defaultEntry, LanguagePacks))
                return;

            try
            {
                await _languagePacks.DownloadCatalogPackAsync(defaultEntry);
                await ScanLanguagePacks();

                var pack = LanguagePacks.FirstOrDefault(p =>
                    string.Equals(System.IO.Path.GetFileName(p.Path), defaultEntry.ZipFileName, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(p.Name, defaultEntry.Name, StringComparison.OrdinalIgnoreCase));

                if (pack != null && pack.CanActivate && DqxDirValid)
                    await SetLanguagePackActive(pack, true);
            }
            catch (Exception ex)
            {
                SetLanguagePackStatus($"Couldn't fetch the default English pack (no URL configured yet). {ex.Message}");
            }
        }
        catch
        {
            // Never let first-run setup throw to the caller.
        }
        finally
        {
            try { _cfg.SaveLanguagePackFirstRunDone(true); } catch { }
        }
    }

    public async Task DownloadLanguagePackUpdate(LanguagePack pack)
    {
        if (!pack.HasUpdate)
            return;

        var wasActive = pack.IsActive;
        try
        {
            LanguagePacksLoading = true;
            pack.Status = "Downloading update...";

            var updated = await _languagePacks.DownloadUpdateAsync(pack);
            pack.Name = updated.Name;
            pack.Author = updated.Author;
            pack.Language = updated.Language;
            pack.Created = updated.Created;
            pack.DownloadUrl = updated.DownloadUrl;
            pack.GameMods = updated.GameMods;
            pack.CanActivate = updated.CanActivate;
            pack.HasUpdate = false;
            pack.IsActive = wasActive;
            pack.Status = wasActive ? "Active" : "Ready";

            if (wasActive && DqxDirValid)
            {
                var activePacks = LanguagePacks.Where(m => m.IsActive && m.CanActivate).ToList();
                var count = await Task.Run(() => _languagePacks.RebuildGameModsFolder(DqxDir, activePacks));
                SetLanguagePackStatus($"Updated {pack.Name}. Game\\mods rebuilt: {count} file(s) extracted.");
            }
            else
            {
                SetLanguagePackStatus($"Updated {pack.Name}.");
            }
        }
        catch (Exception ex)
        {
            pack.Status = $"Update failed: {ex.Message}";
            SetLanguagePackStatus(ex.Message, true);
        }
        finally
        {
            LanguagePacksLoading = false;
        }
    }

    public async Task SetLanguagePackActive(LanguagePack pack, bool enabled)
    {
        if (!DqxDirValid)
        {
            SetLanguagePackStatus("Set a valid DQX folder path before activating language packs.", true);
            return;
        }

        var previousState = pack.IsActive;
        pack.IsActive = enabled;

        try
        {
            LanguagePacksLoading = true;
            var activePacks = LanguagePacks.Where(m => m.IsActive && m.CanActivate).ToList();
            var count = await Task.Run(() => _languagePacks.RebuildGameModsFolder(DqxDir, activePacks));

            foreach (var item in LanguagePacks.Where(m => m.CanActivate))
                item.Status = item.IsActive ? "Active" : "Ready";

            SaveActiveLanguagePackSelection();
            SetLanguagePackStatus(activePacks.Count == 0
                ? "Game\\mods cleaned. No language packs active."
                : $"Game\\mods rebuilt: {activePacks.Count} language pack(s), {count} file(s) extracted.");
        }
        catch (Exception ex)
        {
            pack.IsActive = previousState;
            pack.Status = ex.Message;
            SetLanguagePackStatus(ex.Message, true);
        }
        finally
        {
            LanguagePacksLoading = false;
        }
    }

    private List<string> GetActiveLanguagePackFileNames()
    {
        // Order follows the LanguagePacks collection (precedence / extraction order),
        // not alphabetical — reordering the list changes the persisted order.
        if (!_languagePacksScanned)
            return _savedActiveLanguagePacks.ToList();

        return LanguagePacks
            .Where(m => m.IsActive && m.CanActivate)
            .Select(m => Path.GetFileName(m.Path))
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Moves a pack within the LanguagePacks collection to a new index, re-persists the active
    /// order, and rebuilds Game\mods in the new precedence order when packs are active.
    /// </summary>
    /// <summary>
    /// Cheap visual move within the list — safe to call repeatedly while dragging.
    /// Does NOT persist or rebuild Game\mods; call <see cref="CommitLanguagePackOrderAsync"/>
    /// once on drop to persist the final order. Returns true if the position changed.
    /// </summary>
    public bool MoveLanguagePack(LanguagePack pack, int newIndex)
    {
        var oldIndex = LanguagePacks.IndexOf(pack);
        if (oldIndex < 0) return false;

        newIndex = Math.Clamp(newIndex, 0, LanguagePacks.Count - 1);
        if (newIndex == oldIndex) return false;

        LanguagePacks.Move(oldIndex, newIndex);
        return true;
    }

    /// <summary>
    /// Persists the current list order and rebuilds Game\mods once. Call on drop, not per pointer-move.
    /// </summary>
    public async Task CommitLanguagePackOrderAsync()
    {
        SaveActiveLanguagePackSelection();

        if (!LanguagePackSupport || !DqxDirValid) return;

        try
        {
            LanguagePacksLoading = true;
            var activePacks = LanguagePacks.Where(m => m.IsActive && m.CanActivate).ToList();
            if (activePacks.Count > 0)
            {
                var count = await Task.Run(() => _languagePacks.RebuildGameModsFolder(DqxDir, activePacks));
                SetLanguagePackStatus($"Reordered. Game\\mods rebuilt: {activePacks.Count} language pack(s), {count} file(s) extracted.");
            }
        }
        catch (Exception ex)
        {
            SetLanguagePackStatus(ex.Message, true);
        }
        finally
        {
            LanguagePacksLoading = false;
        }
    }

    private void SaveActiveLanguagePackSelection()
    {
        var fileNames = GetActiveLanguagePackFileNames();
        _savedActiveLanguagePacks.Clear();
        _savedActiveLanguagePacks.UnionWith(fileNames);
        _cfg.SaveActiveLanguagePacks(fileNames);
    }

    public Task SetDqxDir(string dir)
    {
        DqxDirError = "";
        DqxDirValid = false;
        if (_cfg.ValidateDqxDir(dir, out var err))
        {
            DqxDir = dir;
            DqxDirValid = true;
            try { _cfg.SaveGameDir(dir); } catch { }
            InitializeLanguagePacksFolder();
        }
        else
        {
            DqxDir = dir;
            DqxDirError = err;
        }
        return Task.CompletedTask;
    }

    [RelayCommand]
    private void ClearDqxDir()
    {
        DqxDir      = "";
        DqxDirValid = false;
        DqxDirError = "";
        try { _cfg.SaveGameDir(""); } catch { }
    }

    [RelayCommand]
    private async Task OpenDqx()
    {
        try { _cfg.LaunchDqx(DqxDir); }
        catch (Exception ex)
        {
            if (ShowInfoRequested != null)
                await ShowInfoRequested("Executable not found", ex.Message);
        }
    }

    [RelayCommand]
    private async Task OpenDqxConfig()
    {
        try { _cfg.LaunchDqxConfig(DqxDir); }
        catch (Exception ex)
        {
            if (ShowInfoRequested != null)
                await ShowInfoRequested("Executable not found", ex.Message);
        }
    }

    private async Task RunPatch(Func<string, Task> patchFn)
    {
        Patching = true;
        PatchStatus = "";
        PatchIsError = false;
        PatchDownloaded = 0;
        PatchTotal = 0;
        try
        {
            await patchFn(DqxDir);
            Patching = false;
            PatchStatus = "Done!";
            _ = Task.Delay(3000).ContinueWith(_ =>
                Avalonia.Threading.Dispatcher.UIThread.Post(() => PatchStatus = ""));
        }
        catch (Exception ex)
        {
            Patching = false;
            PatchStatus = ex.Message;
            PatchIsError = true;
        }
    }

    [RelayCommand] private Task PatchLauncher()   => RunPatch(_patch.PatchLauncher);
    [RelayCommand] private Task RestoreLauncher()  => RunPatch(_patch.RestoreLauncher);
    [RelayCommand] private Task PatchConfig()      => RunPatch(_patch.PatchConfig);
    [RelayCommand] private Task RestoreConfig()    => RunPatch(_patch.RestoreConfig);
    [RelayCommand] private Task PatchGameFiles()   => RunPatch(_patch.PatchGameFiles);
    [RelayCommand] private Task RestoreGameFiles() => RunPatch(_patch.RestoreGameFiles);

    // ── Update ────────────────────────────────────────────────────────────

    public void SetUpdateService(UpdateService svc) => _updateSvc = svc;

    [RelayCommand]
    private async Task RunUpdater()
    {
        if (UpdateInfo == null || UpdaterRunning || _updateSvc == null) return;
        UpdaterRunning = true;
        try { await _updateSvc.RunUpdaterAsync(UpdateInfo.Version); }
        catch { UpdaterRunning = false; }
    }

    // ── Wiki / GitHub ─────────────────────────────────────────────────────

    [RelayCommand]
    private void OpenWiki() =>
        OpenUrl?.Invoke("https://dqx-translation-project.github.io/");

    [RelayCommand]
    private void OpenGitHub() =>
        OpenUrl?.Invoke("https://github.com/dqx-translation-project/dqxclarity");

    [RelayCommand]
    private void OpenLogFolder()
    {
        try
        {
            var exeDir = Path.GetDirectoryName(Environment.ProcessPath ?? "") ?? "";
            var appDir = exeDir;
            for (int i = 0; i < 4; i++)
            {
                if (File.Exists(Path.Combine(appDir, "main.py")))
                { appDir = Path.GetFullPath(appDir); break; }
                appDir = Path.GetFullPath(Path.Combine(appDir, ".."));
            }
            var logsDir = Path.Combine(appDir, "logs");
            if (!Directory.Exists(logsDir)) Directory.CreateDirectory(logsDir);
            Process.Start(new ProcessStartInfo(logsDir) { UseShellExecute = true });
        }
        catch { }
    }
}
