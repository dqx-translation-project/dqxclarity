using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DqxClarity.Launcher.Models;
using DqxClarity.Launcher.Services;

namespace DqxClarity.Launcher.ViewModels;

public partial class SetupViewModel : ObservableObject
{
    private readonly SetupService _svc;

    public event Action? SetupDone;

    public ObservableCollection<SetupStep> Steps { get; } =
    [
        new() { Id = "path_check",    Label = "Checking installation path"     },
        new() { Id = "python_check",  Label = "Locating Python 3.11 (32-bit)"  },
        new() { Id = "python_install",Label = "Installing Python 3.11.3"        },
        new() { Id = "venv_setup",    Label = "Setting up virtual environment"  },
        new() { Id = "deps_install",  Label = "Installing dependencies"         },
        new() { Id = "verify",        Label = "Verifying installation"          },
    ];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string _errorMessage = "";

    [ObservableProperty] private bool _showUacModal;
    [ObservableProperty] private bool _showLogs;
    [ObservableProperty] private bool _done;

    public ObservableCollection<string> PipLines { get; } = [];

    public bool HasError     => !string.IsNullOrEmpty(ErrorMessage);
    public bool HasPipOutput => PipLines.Count > 0;

    public SetupViewModel(SetupService svc)
    {
        _svc = svc;
        _svc.Progress  += OnProgress;
        _svc.UacPrompt += () => Avalonia.Threading.Dispatcher.UIThread.Post(() => ShowUacModal = true);
        PipLines.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasPipOutput));
    }

    private void OnProgress(SetupEvent e)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            if (e.Step == "pip_output")
            {
                if (!string.IsNullOrWhiteSpace(e.Message))
                    PipLines.Add(e.Message);
                return;
            }

            if (e.Step == "uac_prompt")
            {
                ShowUacModal = true;
                return;
            }

            var step = Steps.FirstOrDefault(s => s.Id == e.Step);
            if (step != null)
            {
                step.Status = e.Status switch
                {
                    "running" => StepStatus.Running,
                    "done"    => StepStatus.Done,
                    "error"   => StepStatus.Error,
                    _         => StepStatus.Pending,
                };
                step.Message = e.Message;
            }

            if (e.Step == "python_install" && e.Status is "done" or "error")
            {
                ShowUacModal = false;
                if (e.Status == "error") ShowLogs = true;
            }
        });
    }

    private void Reset()
    {
        ErrorMessage = "";
        ShowLogs = false;
        PipLines.Clear();
        Done = false;
        foreach (var s in Steps) { s.Status = StepStatus.Pending; s.Message = ""; }
    }

    [RelayCommand]
    private async Task RunSetup()
    {
        Reset();
        try
        {
            await _svc.RunAsync();
            Done = true;
            await Task.Delay(600);
            SetupDone?.Invoke();
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
    }

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

    [RelayCommand]
    private void CloseUac() => ShowUacModal = false;

    [RelayCommand]
    private async Task Retry() => await RunSetup();

    public void StartSetup() => _ = RunSetup();
}
