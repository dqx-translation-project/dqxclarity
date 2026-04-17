using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DqxClarity.Launcher.Models;
using DqxClarity.Launcher.Services;

namespace DqxClarity.Launcher.ViewModels;

public partial class LogViewModel : ObservableObject
{
    private const int MaxLines = 1000;
    private readonly ProcessService _processSvc;

    public event Action? NavigateBack;
    public event Action? CloseApp;

    [ObservableProperty] private bool _exitedWithError;
    [ObservableProperty] private bool _hasExited;
    [ObservableProperty] private bool _showStopWarning;
    [ObservableProperty] private string _statusTitle = "dqxclarity — running";

    public ObservableCollection<LogLine> Lines { get; } = [];
    public bool HasNoLines => Lines.Count == 0;

    public LogViewModel(ProcessService processSvc)
    {
        _processSvc = processSvc;
        _processSvc.LogLine       += OnLogLine;
        _processSvc.ProcessExited += OnProcessExited;
    }

    public void UpdateTitle(string version)
    {
        StatusTitle = ExitedWithError
            ? "dqxclarity — exited with error"
            : $"dqxclarity — running (v{version})";
    }

    private void OnLogLine(LogLine line) =>
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            Lines.Add(line);
            while (Lines.Count > MaxLines)
                Lines.RemoveAt(0);
            OnPropertyChanged(nameof(HasNoLines));
        });

    private void OnProcessExited(bool isError) =>
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            if (!isError)
            {
                CloseApp?.Invoke();
                return;
            }
            ExitedWithError = true;
            HasExited = true;
            StatusTitle = "dqxclarity — exited with error";
        });

    [RelayCommand]
    private void Stop() => _processSvc.Stop();

    [RelayCommand]
    private void Back() => NavigateBack?.Invoke();

    [RelayCommand]
    private void DismissStopWarning() => ShowStopWarning = false;

    public void Reset()
    {
        Lines.Clear();
        ExitedWithError = false;
        HasExited = false;
        StatusTitle = "dqxclarity — running";
        OnPropertyChanged(nameof(HasNoLines));
    }

    public bool TryClose()
    {
        if (_processSvc.IsRunning())
        {
            ShowStopWarning = true;
            return false; // block close
        }
        return true;
    }
}
