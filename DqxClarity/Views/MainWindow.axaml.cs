using System.Runtime.InteropServices;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using DqxClarity.Models;
using DqxClarity.ViewModels;

namespace DqxClarity.Views;

public partial class MainWindow : Window
{
    [DllImport("user32.dll")]                    private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")]                    private static extern IntPtr SetClassLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);
    [DllImport("user32.dll", CharSet = CharSet.Auto)] private static extern IntPtr LoadImage(IntPtr hInst, string name, uint type, int cx, int cy, uint fuLoad);

    private const uint WM_SETICON      = 0x0080;
    private const int  ICON_SMALL      = 0;
    private const int  ICON_BIG        = 1;
    private const int  GCL_HICON       = -14;
    private const int  GCL_HICONSM     = -34;
    private const uint IMAGE_ICON      = 1;
    private const uint LR_LOADFROMFILE = 0x00000010;

    private MainViewModel? _vm;
    private SettingsView?  _settingsView;
    private LogView?       _logView;

    private bool _aboutOpen;
    private bool _supportOpen;
    private bool _stopWarningOpen;
    private Action? _overlayDismissAction;

    public MainWindow()
    {
        InitializeComponent();
    }

    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        Avalonia.Threading.Dispatcher.UIThread.Post(ApplyTaskbarIcon, Avalonia.Threading.DispatcherPriority.Background);
    }

    private void ApplyTaskbarIcon()
    {
        var hwnd = TryGetPlatformHandle()?.Handle ?? IntPtr.Zero;
        if (hwnd == IntPtr.Zero) return;

        try
        {
            // Write the embedded ICO to a temp file — LoadImage with LR_LOADFROMFILE is the
            // most reliable way to get a correctly-sized HICON on Windows.
            var tmp = Path.Combine(Path.GetTempPath(), "dqxclarity_icon.ico");
            using var src = Avalonia.Platform.AssetLoader.Open(new Uri("avares://dqxclarity/Assets/rosie.ico"));
            using var dst = File.Create(tmp);
            src.CopyTo(dst);
            dst.Close();

            var large = LoadImage(IntPtr.Zero, tmp, IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
            var small  = LoadImage(IntPtr.Zero, tmp, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);

            if (large != IntPtr.Zero)
            {
                SendMessage(hwnd, WM_SETICON, (IntPtr)ICON_BIG, large);
                SetClassLongPtr(hwnd, GCL_HICON, large);
            }
            if (small != IntPtr.Zero)
            {
                SendMessage(hwnd, WM_SETICON, (IntPtr)ICON_SMALL, small);
                SetClassLongPtr(hwnd, GCL_HICONSM, small);
            }
        }
        catch { }
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);

        if (DataContext is not MainViewModel vm) return;
        _vm = vm;
        _vm.Window = this;

        // version is displayed inside SettingsView's sidebar

        // Create views once
        _settingsView = new SettingsView { DataContext = vm.Settings };
        _logView      = new LogView      { DataContext = vm.Log      };

        // Wire settings dialogs here (not in SettingsView code-behind) so they work
        // regardless of whether SettingsView is currently in the visual tree (e.g. autorun).
        vm.Settings.ShowInfoRequested += async (title, body) =>
            await ShowInfoAsync(title, body);
        vm.Settings.ShowConfirmRequested += async (title, body) =>
            await ShowConfirmAsync(title, body);
        vm.Settings.ShowOtpDialogRequested += async () =>
            await ShowInputAsync(
                "One-Time Password",
                "Your account has multi-factor authentication enabled. Enter your 6-digit OTP code.");

        // Wire browse button in settings to use Avalonia folder picker
        _settingsView.BrowseFolderRequested += async () =>
        {
            var results = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title         = "Select DQX Installation Folder",
                AllowMultiple = false,
            });
            if (results.Count > 0)
                await vm.Settings.SetDqxDir(results[0].Path.LocalPath);
        };

        // Subscribe to view changes
        vm.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(MainViewModel.CurrentView))
                UpdateView();
        };

        // Show first-launch welcome on initial settings view (no setup step anymore).
        if (vm.IsFirstLaunch)
        {
            Avalonia.Threading.Dispatcher.UIThread.Post(async () =>
            {
                await ShowWelcomeAsync();
                vm.MarkWelcomeSeen();
            });
        }

        // Wire log view's close-intercept
        Closing += (_, args) =>
        {
            if (!vm.TryClose())
            {
                args.Cancel = true;
                _ = ShowStopWarningAsync();
            }
        };

        UpdateView();
    }

    private void UpdateView()
    {
        if (_vm == null) return;

        var view = _vm.CurrentView;
        MainContent.Content = view switch
        {
            "settings" => _settingsView,
            "log"      => _logView,
            _          => _settingsView,
        };

        // footer lives inside SettingsView sidebar — no MainWindow-level visibility toggle needed
    }

    private void OnBannerTapped(object? sender, Avalonia.Input.TappedEventArgs e)
    {
        if (_vm?.BannerUrl is { Length: > 0 } url)
            _vm.OpenBrowser(url);
    }

    private void OnBannerToggleClick(object? sender, RoutedEventArgs e)
    {
        if (_vm != null)
            _vm.IsBannerCollapsed = !_vm.IsBannerCollapsed;
    }

    private void OnBannerPrevClick(object? sender, RoutedEventArgs e) =>
        _ = _vm!.JumpToPrevBannerAsync();

    private void OnBannerNextClick(object? sender, RoutedEventArgs e) =>
        _ = _vm!.JumpToNextBannerAsync();

    private void OnBannerDotTapped(object? sender, Avalonia.Input.TappedEventArgs e)
    {
        e.Handled = true; // prevent bubbling to any parent handlers
        if (sender is Avalonia.Controls.Shapes.Ellipse { DataContext: BannerDotItem dot })
            _ = _vm!.JumpToBannerAsync(dot.Index);
    }

    private void OnAboutClick(object? sender, RoutedEventArgs e) => OpenAbout();
    internal void OpenAbout()
    {
        if (_aboutOpen) return;
        _aboutOpen = true;
        var dlg = new AboutPopup();
        void close() { _aboutOpen = false; HideOverlay(); }
        dlg.RequestClose   += close;
        dlg.RequestOpenUrl += url => _vm?.OpenBrowser(url);
        _overlayDismissAction = close;
        ShowOverlay(dlg);
    }

    private void OnWikiClick(object? sender, RoutedEventArgs e) => OpenWiki();
    internal void OpenWiki() =>
        _vm?.OpenBrowser("https://dqx-translation-project.github.io/");

    private void OnSupportClick(object? sender, RoutedEventArgs e) => OpenSupport();
    internal void OpenSupport()
    {
        if (_supportOpen) return;
        _supportOpen = true;
        var dlg = new SupportPopup();
        void close() { _supportOpen = false; HideOverlay(); }
        dlg.RequestClose += close;
        _overlayDismissAction = close;
        ShowOverlay(dlg);
    }

    // ── Overlay helpers ───────────────────────────────────────────────────

    internal async Task ShowInfoAsync(string title, string body)
    {
        var dlg = new InfoDialog(title, body);
        var tcs = new TaskCompletionSource();
        dlg.RequestClose += () => { HideOverlay(); tcs.TrySetResult(); };
        _overlayDismissAction = () => { HideOverlay(); tcs.TrySetResult(); };
        ShowOverlay(dlg);
        await tcs.Task;
    }

    internal async Task<bool> ShowConfirmAsync(string title, string body)
    {
        var dlg = new ConfirmDialog(title, body);
        var tcs = new TaskCompletionSource<bool>();
        dlg.RequestClose += result => { HideOverlay(); tcs.TrySetResult(result); };
        _overlayDismissAction = () => { HideOverlay(); tcs.TrySetResult(false); };
        ShowOverlay(dlg);
        return await tcs.Task;
    }

    internal async Task<bool> ShowUpdateAsync(UpdateInfo info)
    {
        var dlg = new UpdateDialog(info);
        var tcs = new TaskCompletionSource<bool>();
        dlg.RequestClose += result => { HideOverlay(); tcs.TrySetResult(result); };
        _overlayDismissAction = () => { HideOverlay(); tcs.TrySetResult(false); };
        ShowOverlay(dlg);
        return await tcs.Task;
    }

    internal async Task ShowErrorDetailAsync(string detail)
    {
        var dlg = new ErrorDetailDialog(detail);
        var tcs = new TaskCompletionSource();
        dlg.RequestClose += () => { HideOverlay(); tcs.TrySetResult(); };
        _overlayDismissAction = () => { HideOverlay(); tcs.TrySetResult(); };
        ShowOverlay(dlg);
        await tcs.Task;
    }

    internal async Task<string?> ShowInputAsync(string title, string prompt, bool isPassword = false)
    {
        var dlg = new InputDialog(title, prompt, isPassword);
        var tcs = new TaskCompletionSource<string?>();
        dlg.RequestClose += result => { HideOverlay(); tcs.TrySetResult(result); };
        _overlayDismissAction = () => { HideOverlay(); tcs.TrySetResult(null); };
        ShowOverlay(dlg);
        return await tcs.Task;
    }

    private async Task ShowWelcomeAsync()
    {
        var dlg = new WelcomeDialog();
        var tcs = new TaskCompletionSource();
        dlg.RequestClose += () => { HideOverlay(); tcs.TrySetResult(); };
        // _overlayDismissAction intentionally not set — backdrop clicks do nothing
        ShowOverlay(dlg);
        await tcs.Task;
    }

    private async Task ShowStopWarningAsync()
    {
        if (_stopWarningOpen) return;
        _stopWarningOpen = true;

        var dlg = new ConfirmDialog(
            "dqxclarity is running",
            "You must stop dqxclarity before closing. Click Stop Now to terminate it, or Cancel to return.",
            cancelLabel: "Cancel",
            confirmLabel: "Stop Now",
            confirmIsDanger: true);
        var tcs = new TaskCompletionSource<bool>();
        dlg.RequestClose += result => { _stopWarningOpen = false; HideOverlay(); tcs.TrySetResult(result); };
        _overlayDismissAction = () => { _stopWarningOpen = false; HideOverlay(); tcs.TrySetResult(false); };
        ShowOverlay(dlg);

        if (await tcs.Task)
            _vm?.Log.StopCommand.Execute(null);
    }

    private void OnOverlayBackdropPressed(object? sender, PointerPressedEventArgs e)
    {
        if (ReferenceEquals(e.Source, OverlayPanel))
            _overlayDismissAction?.Invoke();
    }

    internal void ShowNonDismissableOverlay(UserControl content)
    {
        _overlayDismissAction = null;
        ShowOverlay(content);
    }

    internal void DismissOverlay() => HideOverlay();

    private void ShowOverlay(UserControl content)
    {
        OverlayContent.Content = content;
        OverlayPanel.IsVisible = true;
    }

    private void HideOverlay()
    {
        _overlayDismissAction  = null;
        OverlayPanel.IsVisible = false;
        OverlayContent.Content = null;
    }
}
