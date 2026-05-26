using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using DqxClarity.Services;
using DqxClarity.ViewModels;
using DqxClarity.Views;

namespace DqxClarity;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var configSvc      = new ConfigService();
            var updateSvc      = new UpdateService();
            var patchSvc       = new PatchService();
            var dbSvc          = new DatabaseService();
            var validateSvc    = new ValidateService();
            var maintenanceSvc = new MaintenanceService();

            LocaleEmulatorService.EnsureExtracted();
            PacketWardenService.EnsureExtracted();

            var config  = configSvc.Load();
            var version = configSvc.GetVersion();
            var autoRun = configSvc.HasAutorunFlag();

            ThemeService.Apply(config.Launcher.Theme);

            var window = new MainWindow();
            var s2cVm  = new Text2ClipboardViewModel(window.Clipboard, configSvc);

            var mainVm = new MainViewModel(
                config, version, autoRun,
                configSvc, updateSvc, patchSvc, dbSvc, validateSvc, maintenanceSvc, s2cVm);

            window.DataContext = mainVm;
            mainVm.Window = window;
            desktop.MainWindow = window;
        }

        base.OnFrameworkInitializationCompleted();
    }
}
