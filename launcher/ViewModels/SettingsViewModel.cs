using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DqxClarity.Launcher.Models;
using DqxClarity.Launcher.Services;

namespace DqxClarity.Launcher.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly ConfigService   _cfg;
    private readonly PatchService    _patch;
    private readonly DatabaseService _db;
    private readonly ValidateService _validate;
    private UpdateService?           _updateSvc;

    public event Action<List<string>>? RunRequested; // args list
    public event Action? ShowSupportPopup;
    public event Action<string>? OpenUrl;
    public event Func<string, string, Task>? ShowInfoRequested;

    // ── Launcher settings ────────────────────────────────────────────────────
    [ObservableProperty] private bool _nameplates;
    [ObservableProperty] private bool _debugLogging;
    [ObservableProperty] private bool _communityLogging;

    // ── Translation (radio-style) ─────────────────────────────────────────
    [ObservableProperty] private bool   _useDeepL;
    [ObservableProperty] private string _deepLKey = "";
    [ObservableProperty] private bool   _useGoogle;
    [ObservableProperty] private string _googleKey = "";
    [ObservableProperty] private bool   _useGoogleFree;
    [ObservableProperty] private bool   _useCommunityApi;
    [ObservableProperty] private string _communityApiKey = "";

    // ── Theme ─────────────────────────────────────────────────────────────
    [ObservableProperty] private string _selectedTheme = "rosie";

    partial void OnSelectedThemeChanged(string value)
    {
        ThemeService.Apply(value);
        try { _cfg.SaveTheme(value); } catch { }
    }

    // ── Game tab ──────────────────────────────────────────────────────────
    [ObservableProperty] private string _dqxDir = "";
    [ObservableProperty] private bool   _dqxDirValid;
    [ObservableProperty] private string _dqxDirError = "";
    [ObservableProperty] private string _leDir = "";
    [ObservableProperty] private string _leDirError = "";
    [ObservableProperty] private bool   _simultaneousLaunch;
    [ObservableProperty] private bool   _launchSendToChat;

    [ObservableProperty] private bool   _sendToChatInstalled;
    [ObservableProperty] private bool   _sendToChatBusy;
    [ObservableProperty] private string _sendToChatStatus = "";

    [ObservableProperty] private bool   _patching;
    [ObservableProperty] private string _patchStatus = "";
    [ObservableProperty] private bool   _patchIsError;
    [ObservableProperty] private long   _patchDownloaded;
    [ObservableProperty] private long   _patchTotal;

    // ── UI state ─────────────────────────────────────────────────────────
    [ObservableProperty] private string _activeTab = "general";
    [ObservableProperty] private string _statusMsg = "";
    [ObservableProperty] private bool   _validating;
    [ObservableProperty] private string _hintText = "";
    [ObservableProperty] private bool   _updaterRunning;
    [ObservableProperty] private bool   _showDbHelp;
    [ObservableProperty] private bool   _showCommunityApiInfo;
    // ── Name overrides ────────────────────────────────────────────────────
    [ObservableProperty] private string _nameOverridesContent = "";
    [ObservableProperty] private string _overridesSaveError = "";
    [ObservableProperty] private bool   _overridesSaveSuccess;
    private bool _nameOverridesLoaded;

    // ── Database ──────────────────────────────────────────────────────────
    [ObservableProperty] private bool   _dbLoading;
    [ObservableProperty] private string _dbError = "";
    [ObservableProperty] private string _dbSelectedTable = "";
    [ObservableProperty] private string _dbRowCount = "";
    [ObservableProperty] private string _dbFilter = "";
    [ObservableProperty] private bool   _dbDeleteConfirm;
    [ObservableProperty] private bool   _dbPurgeConfirm;

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

    /// <summary>
    /// Text shown in the left side of the bottom bar when hovering a control.
    /// </summary>
    public string UpdateBarText =>
        !string.IsNullOrEmpty(HintText) ? HintText : "";

    /// <summary>
    /// Label for the update button, e.g. "Update to 1.2.3".
    /// </summary>
    public string UpdateButtonText =>
        UpdateInfo != null ? $"Update to {UpdateInfo.Version}" : "";

    public void SetUpdateInfo(UpdateInfo info) => UpdateInfo = info;

    private bool _gameTabInitialized;

    public SettingsViewModel(
        AppConfig config,
        string version,
        UpdateInfo? updateInfo,
        ConfigService cfg,
        PatchService patch,
        DatabaseService db,
        ValidateService validate)
    {
        _cfg      = cfg;
        _patch    = patch;
        _db       = db;
        _validate = validate;

        Version    = version;
        _updateInfo = updateInfo;

        _nameplates        = config.Launcher.Nameplates;
        _debugLogging      = config.Launcher.DebugLogging;
        _communityLogging  = config.Launcher.CommunityLogging;
        _simultaneousLaunch  = config.Launcher.SimultaneousLaunch;
        _launchSendToChat    = config.Launcher.LaunchSendToChat;
        _sendToChatInstalled = cfg.SendToChatInstalled();
        _selectedTheme     = config.Launcher.Theme;

        _useDeepL          = config.Translation.EnableDeepLTranslate;
        _deepLKey          = config.Translation.DeepLTranslateKey;
        _useGoogle         = config.Translation.EnableGoogleTranslate;
        _googleKey         = config.Translation.GoogleTranslateKey;
        _useGoogleFree     = config.Translation.EnableGoogleTranslateFree;
        _useCommunityApi   = config.Translation.EnableCommunityApi;
        _communityApiKey   = config.Translation.CommunityApiKey;

        _dqxDir = config.Game.InstallDirectory;
        _leDir  = config.Game.LocaleEmulatorDirectory;

        _patch.Progress += (downloaded, total) =>
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                PatchDownloaded = downloaded;
                PatchTotal = total;
            });
    }

    // ── Tab activation ───────────────────────────────────────────────────

    [RelayCommand]
    private void ActivateTab(string tab)
    {
        ActiveTab = tab;
        if (tab == "nameoverrides" && !_nameOverridesLoaded)
        {
            _nameOverridesLoaded = true;
            NameOverridesContent = _cfg.ReadNameOverrides();
        }
        if (tab == "game" && !_gameTabInitialized)
        {
            _gameTabInitialized = true;
            if (!string.IsNullOrEmpty(DqxDir))
                DqxDirValid = _cfg.ValidateDqxDir(DqxDir, out _);
        }
    }

    // ── Translation toggles (radio-style: checking one unchecks the others) ─

    private bool _translationUpdating;

    partial void OnUseDeepLChanged(bool value)
    {
        if (_translationUpdating) return;
        _translationUpdating = true;
        if (value) { UseGoogle = false; UseGoogleFree = false; }
        OnPropertyChanged(nameof(CanValidate));
        _translationUpdating = false;
    }

    partial void OnUseGoogleChanged(bool value)
    {
        if (_translationUpdating) return;
        _translationUpdating = true;
        if (value) { UseDeepL = false; UseGoogleFree = false; }
        OnPropertyChanged(nameof(CanValidate));
        _translationUpdating = false;
    }

    partial void OnUseGoogleFreeChanged(bool value)
    {
        if (_translationUpdating) return;
        _translationUpdating = true;
        if (value) { UseDeepL = false; UseGoogle = false; }
        OnPropertyChanged(nameof(CanValidate));
        _translationUpdating = false;
    }

    partial void OnValidatingChanged(bool value) => OnPropertyChanged(nameof(CanValidate));

    // ── Validation ────────────────────────────────────────────────────────

    public bool CanValidate => !Validating && (UseDeepL || UseGoogle);

    [RelayCommand]
    private async Task ValidateKey()
    {
        Validating = true;
        StatusMsg = "Validating…";
        try
        {
            if (UseDeepL)
                StatusMsg = await _validate.ValidateDeepLKey(DeepLKey);
            else if (UseGoogle)
                StatusMsg = await _validate.ValidateGoogleKey(GoogleKey);
            else
                StatusMsg = "Enable an API service before validating.";
        }
        catch (Exception ex)
        {
            StatusMsg = ex.Message;
        }
        Validating = false;
    }

    // ── Run ───────────────────────────────────────────────────────────────

    [RelayCommand]
    private async Task Run()
    {
        var missing = new List<string>();
        if (UseDeepL        && string.IsNullOrWhiteSpace(DeepLKey))        missing.Add("DeepL");
        if (UseGoogle       && string.IsNullOrWhiteSpace(GoogleKey))       missing.Add("Google Translate");
        if (UseCommunityApi && string.IsNullOrWhiteSpace(CommunityApiKey)) missing.Add("Community API");

        if (missing.Count > 0)
        {
            if (ShowInfoRequested != null)
                await ShowInfoRequested("Missing API Keys",
                    $"The following enabled API services have no key entered:\n\n  • {string.Join("\n  • ", missing)}\n\nEnter the missing key(s) before running.");
            return;
        }

        var launcher = new LauncherConfig
        {
            Nameplates         = Nameplates,
            DebugLogging       = DebugLogging,
            CommunityLogging   = CommunityLogging,
            SimultaneousLaunch = SimultaneousLaunch,
            LaunchSendToChat   = LaunchSendToChat,
            Theme              = SelectedTheme,
        };
        var translation = new TranslationConfig
        {
            EnableDeepLTranslate      = UseDeepL,
            DeepLTranslateKey         = DeepLKey,
            EnableGoogleTranslate     = UseGoogle,
            GoogleTranslateKey        = GoogleKey,
            EnableGoogleTranslateFree = UseGoogleFree,
            EnableCommunityApi        = UseCommunityApi,
            CommunityApiKey           = CommunityApiKey,
        };
        try { _cfg.Save(launcher, translation); } catch { }

        if (SimultaneousLaunch && !string.IsNullOrEmpty(DqxDir))
            try { _cfg.LaunchDqx(DqxDir, string.IsNullOrEmpty(LeDir) ? null : LeDir); } catch { }

        if (LaunchSendToChat && SendToChatInstalled)
            try { _cfg.LaunchSendToChat(); } catch { }

        var args = new List<string>();
        if (Nameplates)       args.Add("--nameplates");
        if (DebugLogging)     args.Add("--debug");
        if (CommunityLogging) args.Add("--community-logging");
        if (UseDeepL || UseGoogle || UseGoogleFree) args.Add("--communication-window");

        RunRequested?.Invoke(args);
        await Task.CompletedTask;
    }

    // ── Name overrides ────────────────────────────────────────────────────

    [RelayCommand]
    private void SaveNameOverrides()
    {
        OverridesSaveError   = "";
        OverridesSaveSuccess = false;

        JsonDocument? doc = null;
        try
        {
            doc = JsonDocument.Parse(NameOverridesContent);
        }
        catch (Exception ex)
        {
            OverridesSaveError = $"Save failed: invalid JSON — {ex.Message}";
            return;
        }

        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            OverridesSaveError = "Save failed: root value must be an object.";
            return;
        }
        foreach (var required in new[] { "player_names", "mytown_names" })
        {
            if (!root.TryGetProperty(required, out var prop))
                { OverridesSaveError = $"Save failed: missing required key \"{required}\"."; return; }
            if (prop.ValueKind != JsonValueKind.Object)
                { OverridesSaveError = $"Save failed: \"{required}\" must be an object."; return; }
        }

        var pretty = JsonSerializer.Serialize(
            JsonSerializer.Deserialize<object>(NameOverridesContent),
            new JsonSerializerOptions { WriteIndented = true });

        try
        {
            _cfg.SaveNameOverrides(pretty);
            NameOverridesContent = pretty;
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

    public int DbSelectedCount => _dbRows.Count(r => r.Selected);

    [RelayCommand]
    private void InitiateDelete()
    {
        if (_dbRows.Any(r => r.Selected))
            DbDeleteConfirm = true;
    }

    [RelayCommand]
    private async Task ConfirmDbDelete()
    {
        DbDeleteConfirm = false;
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
            DbPurgeConfirm = false;
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

    [RelayCommand]
    private async Task BrowseDqxDir()
    {
        // Folder selection delegated to View via OpenFolderDialog
        // The view will call SetDqxDir() with the result
        await Task.CompletedTask;
    }

    public async Task SetDqxDir(string dir)
    {
        DqxDirError = "";
        DqxDirValid = false;
        if (_cfg.ValidateDqxDir(dir, out var err))
        {
            DqxDir = dir;
            DqxDirValid = true;
            try { _cfg.SaveGameDir(dir); } catch { }
        }
        else
        {
            DqxDir = dir;
            DqxDirError = err;
        }
        await Task.CompletedTask;
    }

    public async Task SetLeDir(string dir)
    {
        LeDirError = "";
        if (_cfg.ValidateLocaleEmulatorDir(dir, out var err))
        {
            LeDir = dir;
            try { _cfg.SaveLocaleEmulatorDir(dir); } catch { }
        }
        else
        {
            LeDir = dir;
            LeDirError = err;
        }
        await Task.CompletedTask;
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
    private void ClearLeDir()
    {
        LeDir      = "";
        LeDirError = "";
        try { _cfg.SaveLocaleEmulatorDir(""); } catch { }
    }

    [RelayCommand]
    private async Task OpenDqx()
    {
        try { _cfg.LaunchDqx(DqxDir, string.IsNullOrEmpty(LeDir) ? null : LeDir); }
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

    [RelayCommand]
    private async Task OpenSendToChat()
    {
        try { _cfg.LaunchSendToChat(); }
        catch (Exception ex)
        {
            if (ShowInfoRequested != null)
                await ShowInfoRequested("Executable not found", ex.Message);
        }
    }

    [RelayCommand]
    private async Task InstallSendToChat()
    {
        if (SendToChatBusy) return;
        SendToChatBusy   = true;
        SendToChatStatus = "Downloading...";
        try
        {
            var destPath = _cfg.SendToChatExePath();
            Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);

            using var http = new HttpClient();
            http.DefaultRequestHeaders.UserAgent.ParseAdd("dqxclarity-launcher/1.0");

            var json = await http.GetStringAsync(
                "https://api.github.com/repos/dqx-translation-project/dqx-send-to-chat/releases/latest");
            using var doc = System.Text.Json.JsonDocument.Parse(json);

            string? downloadUrl = null;
            foreach (var asset in doc.RootElement.GetProperty("assets").EnumerateArray())
            {
                if (asset.GetProperty("name").GetString() == "send_to_chat.exe")
                {
                    downloadUrl = asset.GetProperty("browser_download_url").GetString();
                    break;
                }
            }

            if (downloadUrl == null)
                throw new Exception("send_to_chat.exe not found in latest release assets.");

            var bytes = await http.GetByteArrayAsync(downloadUrl);
            await File.WriteAllBytesAsync(destPath, bytes);

            SendToChatInstalled = File.Exists(destPath);
            SendToChatStatus = "Installed!";
            _ = Task.Delay(3000).ContinueWith(_ =>
                Avalonia.Threading.Dispatcher.UIThread.Post(() => SendToChatStatus = ""));
        }
        catch (Exception ex)
        {
            SendToChatStatus = $"Failed: {ex.Message}";
        }
        finally
        {
            SendToChatBusy = false;
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
    private void OpenSupport() => ShowSupportPopup?.Invoke();

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
