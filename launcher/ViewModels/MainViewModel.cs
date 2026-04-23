using Avalonia.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using DqxClarity.Launcher.Models;
using DqxClarity.Launcher.Services;

namespace DqxClarity.Launcher.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly ConfigService  _cfg;
    private readonly UpdateService  _updateSvc;
    private readonly ProcessService _processSvc;

    public SetupViewModel    Setup    { get; }
    public SettingsViewModel Settings { get; }
    public LogViewModel      Log      { get; }
    public Send2ChatViewModel Send2Chat { get; }

    public string Version { get; }

    [ObservableProperty] private string _currentView = "setup";

    // Set by MainWindow after construction
    public Window? Window { get; set; }

    private static readonly Dictionary<string, (double W, double H)> WinSizes = new()
    {
        ["setup"]    = (680, 580),
        ["settings"] = (680, 580),
        ["log"]      = (680, 580),
    };

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
        Send2ChatViewModel send2Chat)
    {
        _cfg        = cfg;
        _updateSvc  = updateSvc;
        _processSvc = processSvc;
        Version     = version;
        Send2Chat = send2Chat;

        Setup    = new SetupViewModel(setupSvc);
        Log      = new LogViewModel(processSvc, send2Chat);
        Settings = new SettingsViewModel(
            config, version, null, send2Chat, cfg, patchSvc, dbSvc, validateSvc);

        Setup.SetupDone     += () => SwitchTo(autoRun ? "log" : "settings");
        Log.NavigateBack    += () => SwitchTo("settings");
        Log.CloseApp        += () => Window?.Close();
        Settings.RunRequested += OnRunRequested;
        Settings.OpenUrl      += OpenBrowser;

        // If autorun, also launch the process after setup
        if (autoRun)
        {
            Setup.SetupDone += () =>
            {
                if (config.Launcher.SimultaneousLaunch && !string.IsNullOrEmpty(config.Game.InstallDirectory))
                    try { _cfg.LaunchDqx(config.Game.InstallDirectory); } catch { }

                Log.UpdateTitle(version);
                _processSvc.Launch(BuildArgs(config));

                // Minimize window
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
    }

    private static List<string> BuildArgs(AppConfig cfg)
    {
        var args = new List<string>();
        if (cfg.Launcher.Nameplates)       args.Add("--nameplates");
        if (cfg.Launcher.DebugLogging)     args.Add("--debug");
        if (cfg.Launcher.CommunityLogging) args.Add("--community-logging");
        var t = cfg.Translation;
        if (t.EnableDeepLTranslate || t.EnableGoogleTranslate || t.EnableGoogleTranslateFree)
            args.Add("--communication-window");
        return args;
    }

    private void OnRunRequested(List<string> args)
    {
        Log.Reset();
        SwitchTo("log");
        Log.UpdateTitle(Version);
        _processSvc.Launch(args);
    }

    public void SwitchTo(string view)
    {
        CurrentView = view;
        if (Window == null || !WinSizes.TryGetValue(view, out var size)) return;

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
}
