using System.Collections.ObjectModel;
using Avalonia.Controls;
using Avalonia.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using DqxClarity.Launcher.Models;
using DqxClarity.Launcher.Services;

namespace DqxClarity.Launcher.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly AppConfig      _config;
    private readonly ConfigService  _cfg;
    private readonly UpdateService  _updateSvc;
    private readonly ProcessService _processSvc;
    private readonly BannerService  _bannerSvc = new();

    public SetupViewModel    Setup    { get; }
    public SettingsViewModel Settings { get; }
    public LogViewModel      Log      { get; }
    public Text2ClipboardViewModel Text2Clipboard { get; }

    public string Version { get; }

    [ObservableProperty] private string  _currentView      = "setup";
    [ObservableProperty] private Bitmap? _bannerImage;
    [ObservableProperty] private string  _bannerUrl        = "";
    [ObservableProperty] private double  _bannerOpacity    = 1;
    [ObservableProperty] private bool    _isBannerCollapsed;

    public bool ShowBanner => CurrentView == "settings";

    partial void OnCurrentViewChanged(string value) =>
        OnPropertyChanged(nameof(ShowBanner));

    partial void OnIsBannerCollapsedChanged(bool value)
    {
        _cfg.SaveBannerCollapsed(value);
    }

    // Set by MainWindow after construction
    public Window? Window { get; set; }

    // Loaded banners (item + bitmap pairs, only entries where image loaded OK)
    private List<(BannerItem Item, Bitmap Image)> _banners = [];
    private int                                    _bannerIdx    = 0;
    private int                                    _bannerStripH = 0;
    private Avalonia.Threading.DispatcherTimer?    _bannerTimer;

    public ObservableCollection<BannerDotItem> BannerDots { get; } = [];

    public MainViewModel(
        AppConfig config,
        string version,
        bool autoRun,
        ConfigService cfg,
        SetupService setupSvc,
        ProcessService processSvc,
        UpdateService updateSvc,
        PatchService patchSvc,
        DatabaseService dbSvc,
        ValidateService validateSvc,
        MaintenanceService maintenanceSvc,
        LanguagePackService langPackSvc,
        Text2ClipboardViewModel text2Clipboard)
    {
        _config     = config;
        _cfg        = cfg;
        _updateSvc  = updateSvc;
        _processSvc = processSvc;
        Version     = version;
        _isBannerCollapsed = config.Launcher.BannerCollapsed;
        Text2Clipboard = text2Clipboard;

        Setup    = new SetupViewModel(setupSvc);
        Log      = new LogViewModel(processSvc, text2Clipboard);
        Settings = new SettingsViewModel(
            config, version, null, text2Clipboard, cfg, patchSvc, dbSvc, validateSvc, maintenanceSvc, langPackSvc);
        Settings.CleanupLanguagePackRuntime();

        Setup.SetupDone     += () => SwitchTo(autoRun ? "log" : "settings");
        Log.NavigateBack    += () => SwitchTo("settings");
        Log.CloseApp        += () => Window?.Close();
        Settings.RunRequested += OnRunRequested;
        Settings.OpenUrl      += OpenBrowser;
        _processSvc.ProcessExited += _ => Settings.CleanupLanguagePackRuntime();

        // If autorun, trigger the full run flow (respects DirectLogin, SimultaneousLaunch, etc.)
        if (autoRun)
        {
            Setup.SetupDone += async () =>
            {
                await Settings.Run();

                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    if (Window != null)
                        Window.WindowState = Avalonia.Controls.WindowState.Minimized;
                });
            };
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

        // Start setup immediately after UI is ready
        Avalonia.Threading.Dispatcher.UIThread.Post(() => Setup.StartSetup());

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

    private static List<string> BuildArgs(AppConfig cfg)
    {
        var args = new List<string>();
        if (cfg.Launcher.Nameplates)       args.Add("--nameplates");
        if (cfg.Launcher.DebugLogging)     args.Add("--debug");
        if (cfg.Launcher.CommunityLogging) args.Add("--community-logging");
        if (!string.IsNullOrEmpty(cfg.Translation.TranslateService)
            && cfg.Translation.TranslateService != "none")
            args.Add("--communication-window");
        return args;
    }

    private void OnRunRequested(List<string> args)
    {
        Log.Reset();
        SwitchTo("log");
        Log.UpdateTitle(Version);
        try
        {
            _processSvc.Launch(args);
        }
        catch
        {
            Settings.CleanupLanguagePackRuntime();
            throw;
        }
    }

    public void SwitchTo(string view)
    {
        CurrentView = view;
        if (Window == null) return;
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
