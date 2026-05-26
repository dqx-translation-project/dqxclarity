using System.Collections.ObjectModel;
using Avalonia.Controls;
using Avalonia.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using DqxClarity.Hooking;
using DqxClarity.Models;
using DqxClarity.Services;
using DqxClarity.Translation.Backends;

namespace DqxClarity.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly AppConfig      _config;
    private readonly ConfigService  _cfg;
    private readonly UpdateService  _updateSvc;
    private readonly BannerService  _bannerSvc = new();

    // Lazy in-process translation runtime — owns the named pipe + PacketWarden
    // injection. Stays alive for the rest of the process lifetime; the pipe
    // accepts the game's hook dll on every fresh game launch.
    private ClarityRuntime? _runtime;

    public SettingsViewModel Settings { get; }
    public LogViewModel      Log      { get; }
    public Text2ClipboardViewModel Text2Clipboard { get; }

    public string Version { get; }

    [ObservableProperty] private string  _currentView      = "settings";
    [ObservableProperty] private Bitmap? _bannerImage;
    [ObservableProperty] private string  _bannerUrl        = "";
    [ObservableProperty] private double  _bannerOpacity    = 1;
    [ObservableProperty] private bool    _isBannerCollapsed;

    public bool ShowBanner => CurrentView == "settings";

    partial void OnCurrentViewChanged(string value) =>
        OnPropertyChanged(nameof(ShowBanner));

    partial void OnIsBannerCollapsedChanged(bool value)
    {
        if (Window == null || CurrentView != "settings") return;
        var newH = GetWinSize("settings").H;
        Window.MaxHeight = newH;
        Window.Height    = newH;
    }

    // Set by MainWindow after construction
    public Window? Window { get; set; }

    // Loaded banners (item + bitmap pairs, only entries where image loaded OK)
    private List<(BannerItem Item, Bitmap Image)> _banners = [];
    private int                                    _bannerIdx    = 0;
    private int                                    _bannerStripH = 0;
    private Avalonia.Threading.DispatcherTimer?    _bannerTimer;

    public ObservableCollection<BannerDotItem> BannerDots { get; } = [];

    private (double W, double H) GetWinSize(string view) => view switch
    {
        "settings" => (680, 580 + (IsBannerCollapsed ? 0 : _bannerStripH)),
        _          => (680, 580),
    };

    public MainViewModel(
        AppConfig config,
        string version,
        bool autoRun,
        ConfigService cfg,
        UpdateService updateSvc,
        PatchService patchSvc,
        DatabaseService dbSvc,
        ValidateService validateSvc,
        MaintenanceService maintenanceSvc,
        Text2ClipboardViewModel text2Clipboard)
    {
        _config     = config;
        _cfg        = cfg;
        _updateSvc  = updateSvc;
        Version     = version;
        Text2Clipboard = text2Clipboard;

        Log      = new LogViewModel(text2Clipboard);
        Settings = new SettingsViewModel(
            config, version, null, text2Clipboard, cfg, patchSvc, dbSvc, validateSvc, maintenanceSvc);

        Log.NavigateBack    += () => SwitchTo("settings");
        Log.StopRequested   += StopRuntime;
        Settings.RunRequested += OnRunRequested;
        Settings.OpenUrl      += OpenBrowser;

        // Start the runtime up front so PostInjectCallback is wired before the
        // user clicks Run — the direct-login flow calls GameLaunchService.Launch
        // immediately and reads PostInjectCallback at that point, which is
        // before RunRequested fires.
        EnsureNativeRuntime();

        if (autoRun)
        {
            // Trigger the full run flow (respects DirectLogin, SimultaneousLaunch,
            // missing-key prompts, etc.) — same path as the Run button. Async
            // posted on the UI thread so we don't block constructor return.
            Avalonia.Threading.Dispatcher.UIThread.Post(async () =>
            {
                await Settings.Run();

                if (Window != null)
                    Window.WindowState = Avalonia.Controls.WindowState.Minimized;
            });
        }

        // Check for updates in background (don't block startup)
        _ = Task.Run(async () =>
        {
            var info = await updateSvc.CheckAsync();
            if (info != null)
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    Settings.SetUpdateInfo(info);
                });
        });

        // Load rotation banners in background
        _ = Task.Run(LoadBannersAsync);
    }

    private async Task LoadBannersAsync()
    {
        var items = await _bannerSvc.GetAllAsync();
        if (items.Count == 0) return;

        // Load first image immediately so it shows fast
        var first = await _bannerSvc.LoadImageAsync(items[0].ImageUrl);
        if (first == null) return;

        _banners.Add((items[0], first));

        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            BannerUrl   = items[0].LinkUrl;
            BannerImage = first;

            // Natural display height at 680px width + dots row + toggle bar
            var pxW = first.PixelSize.Width;
            var pxH = first.PixelSize.Height;
            _bannerStripH = (int)Math.Min(pxH * 680.0 / pxW, 350) + 24;

            // Resize window if already sitting on settings
            if (CurrentView == "settings")
                SwitchTo("settings");

            RefreshDots();
        });

        // Load remaining images in background
        for (var i = 1; i < items.Count; i++)
        {
            var bmp = await _bannerSvc.LoadImageAsync(items[i].ImageUrl);
            if (bmp != null) _banners.Add((items[i], bmp));
        }

        // Start rotation once we have at least two banners; refresh dots for full count
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            RefreshDots();

            if (_banners.Count > 1)
            {
                _bannerTimer = new Avalonia.Threading.DispatcherTimer
                {
                    Interval = TimeSpan.FromSeconds(6)
                };
                _bannerTimer.Tick += async (_, _) => await AdvanceBannerAsync();
                _bannerTimer.Start();
            }
        });
    }

    private async Task AdvanceBannerAsync()
    {
        if (_banners.Count < 2) return;

        BannerOpacity = 0;
        await Task.Delay(420); // slightly more than transition duration

        _bannerIdx  = (_bannerIdx + 1) % _banners.Count;
        BannerImage = _banners[_bannerIdx].Image;
        BannerUrl   = _banners[_bannerIdx].Item.LinkUrl;
        RefreshDots();

        BannerOpacity = 1;
    }

    public Task JumpToPrevBannerAsync() =>
        JumpToBannerAsync((_bannerIdx - 1 + _banners.Count) % _banners.Count);

    public Task JumpToNextBannerAsync() =>
        JumpToBannerAsync((_bannerIdx + 1) % _banners.Count);

    public async Task JumpToBannerAsync(int idx)
    {
        if (idx < 0 || idx >= _banners.Count || idx == _bannerIdx) return;

        _bannerTimer?.Stop();

        BannerOpacity = 0;
        await Task.Delay(420);

        _bannerIdx  = idx;
        BannerImage = _banners[idx].Image;
        BannerUrl   = _banners[idx].Item.LinkUrl;
        RefreshDots();

        BannerOpacity = 1;

        _bannerTimer?.Start();
    }

    private void RefreshDots()
    {
        BannerDots.Clear();
        // Only render dots when there's more than one banner to navigate
        if (_banners.Count <= 1) return;
        for (var i = 0; i < _banners.Count; i++)
            BannerDots.Add(new BannerDotItem { Index = i, IsActive = i == _bannerIdx });
    }

    private void OnRunRequested(List<string> _ignored)
    {
        Log.Reset();
        SwitchTo("log");
        Log.UpdateTitle(Version);
        EnsureNativeRuntime();
        Log.AppendLine("Translation runtime active. Pipe waiting for PacketWarden.dll.");
    }

    // Lazy-construct + start the in-process translation runtime. Subsequent calls
    // are no-ops. The runtime stays alive until the process exits; the pipe will
    // accept the game's hook dll on every fresh game launch.
    private void EnsureNativeRuntime()
    {
        if (_runtime != null) return;
        try
        {
            // Debug-discovery: env var is picked up by PacketWarden.dll on
            // hook-install (one-shot read). Setting it on this process means
            // both Process.Start (default UseShellExecute=false) and
            // CreateProcessW (null lpEnvironment) propagate it into DQXGame.exe.
            // Cleared when debug is off so a re-toggle doesn't leak across
            // restarts of the game in the same launcher session.
            Environment.SetEnvironmentVariable(
                "DQXCLARITY_FORWARD_ALL",
                _config.Launcher.DebugLogging ? "1" : null);

            var backend = BackendFactory.Create(_config.Translation);
            _runtime = new ClarityRuntime(backend, _config.Launcher.DebugLogging);
            if (_config.Launcher.DebugLogging)
            {
                Log.EnableDebug();
                _runtime.SetDebugCallback((typeName, rawLen, hexDump, modLen, modifiedHex) =>
                    Avalonia.Threading.Dispatcher.UIThread.Post(
                        () => Log.Debug?.AddPacket(typeName, rawLen, hexDump, modLen, modifiedHex)));
            }
            _runtime.Start();
            Settings.PostInjectCallback = hProc => _runtime.InjectInto(hProc);

            // Background watcher covers the case where the game is launched
            // outside the launcher (DQXBoot, manual launch). The direct-login
            // path still injects immediately via PostInjectCallback.
            _runtime.StartWatchingForGame((msg, isError) =>
                Avalonia.Threading.Dispatcher.UIThread.Post(
                    () => Log.AppendLine(msg, isError ? "error" : "info")));

            // When the game process exits, run the same teardown as the Stop
            // button: dispose the runtime (closes pipe, log tail, watcher) and
            // return to the settings view.
            _runtime.GameExited += () =>
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    StopRuntime();
                    SwitchTo("settings");
                });
        }
        catch (Exception ex)
        {
            Log.AppendLine($"Failed to start translation runtime: {ex.Message}", "error");
            _runtime = null;
            Settings.PostInjectCallback = null;
        }
    }

    private void StopRuntime()
    {
        _runtime?.Stop();
        _runtime?.Dispose();
        _runtime = null;
        Settings.PostInjectCallback = null;
    }

    public void SwitchTo(string view)
    {
        CurrentView = view;
        if (Window == null) return;

        var size     = GetWinSize(view);
        var sameSize = Math.Abs(Window.Width - size.W) < 1 && Math.Abs(Window.Height - size.H) < 1;

        if (!sameSize)
        {
            // Hide during resize+reposition so the user never sees an intermediate state
            Window.Opacity = 0;

            Window.MaxWidth  = size.W;
            Window.MaxHeight = size.H;
            Window.Width     = size.W;
            Window.Height    = size.H;

            var screen = Window.Screens?.Primary;
            if (screen != null)
            {
                var scaling = screen.Scaling;
                var wa      = screen.WorkingArea;
                Window.Position = new Avalonia.PixelPoint(
                    (int)(wa.X + (wa.Width  - size.W * scaling) / 2),
                    (int)(wa.Y + (wa.Height - size.H * scaling) / 2));
            }

            // Restore after layout has settled
            Avalonia.Threading.Dispatcher.UIThread.Post(
                () => Window.Opacity = 1,
                Avalonia.Threading.DispatcherPriority.Background);
        }
    }

    public void OpenBrowser(string url)
    {
        try
        {
            System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch { }
    }

    public bool TryClose() => Log.TryClose();

    public bool IsFirstLaunch => !_config.Launcher.SeenWelcomeMessage;

    public void MarkWelcomeSeen()
    {
        _config.Launcher.SeenWelcomeMessage = true;
        _cfg.SaveSeenWelcomeMessage();
    }
}
