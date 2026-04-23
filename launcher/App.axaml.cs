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
            var configSvc   = new ConfigService();
            var setupSvc    = new SetupService();
            var processSvc  = new ProcessService();
            var updateSvc   = new UpdateService();
            var patchSvc    = new PatchService();
            var dbSvc       = new DatabaseService();
            var validateSvc = new ValidateService();
            var s2cMemory   = new Send2ChatMemoryService();
            var s2cInput    = new Send2ChatInputService();
            var s2cVm       = new Send2ChatViewModel(s2cMemory, s2cInput);

            var config  = configSvc.Load();
            var version = configSvc.GetVersion();
            var autoRun = configSvc.HasAutorunFlag();

            ThemeService.Apply(config.Launcher.Theme);

            var mainVm = new MainViewModel(
                config, version, autoRun,
                configSvc, setupSvc, processSvc, updateSvc, patchSvc, dbSvc, validateSvc, s2cVm);

            var window = new MainWindow { DataContext = mainVm };
            mainVm.Window = window;
            desktop.MainWindow = window;
            desktop.Exit += (_, _) => s2cMemory.Dispose();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
