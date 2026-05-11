using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using DqxClarity.Launcher.Services;
using DqxClarity.Launcher.ViewModels;
using DqxClarity.Launcher.Views;

namespace DqxClarity.Launcher;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var configSvc      = new ConfigService();
            var setupSvc       = new SetupService();
            var processSvc     = new ProcessService();
            var updateSvc      = new UpdateService();
            var patchSvc       = new PatchService();
            var dbSvc          = new DatabaseService();
            var validateSvc    = new ValidateService();
            var maintenanceSvc = new MaintenanceService();

            LocaleEmulatorService.EnsureExtracted();

            var config  = configSvc.Load();
            var version = configSvc.GetVersion();
            var autoRun = configSvc.HasAutorunFlag();

            ThemeService.Apply(config.Launcher.Theme);

            var window = new MainWindow();
            var s2cVm  = new Text2ClipboardViewModel(window.Clipboard);

            var mainVm = new MainViewModel(
                config, version, autoRun,
                configSvc, setupSvc, processSvc, updateSvc, patchSvc, dbSvc, validateSvc, maintenanceSvc, s2cVm);

            window.DataContext = mainVm;
            mainVm.Window = window;
            desktop.MainWindow = window;
        }

        base.OnFrameworkInitializationCompleted();
    }
}
