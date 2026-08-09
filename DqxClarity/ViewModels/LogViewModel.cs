using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DqxClarity.Models;

namespace DqxClarity.ViewModels;

public partial class LogViewModel : ObservableObject
{
    private const int MaxLines = 1000;

    public event Action? NavigateBack;
    public event Action? StopRequested;

    [ObservableProperty] private bool _exitedWithError;
    [ObservableProperty] private bool _hasExited;
    [ObservableProperty] private bool _showStopWarning;
    [ObservableProperty] private string _statusTitle = "dqxclarity - running";
    [ObservableProperty] private string _activeLogTab = "dqxclarity";

    public Text2ClipboardViewModel Text2Clipboard { get; }
    public DebugViewModel? Debug { get; private set; }

    [ObservableProperty] private bool _debugEnabled;

    public ObservableCollection<LogLine> Lines { get; } = [];
    public bool HasNoLines => Lines.Count == 0;

    public LogViewModel(Text2ClipboardViewModel text2Clipboard)
    {
        Text2Clipboard = text2Clipboard;
    }

    public void EnableDebug()
    {
        Debug = new DebugViewModel();
        DebugEnabled = true;
        OnPropertyChanged(nameof(Debug));
    }

    public void UpdateTitle(string version)
    {
        StatusTitle = ExitedWithError
            ? "dqxclarity - exited with error"
            : $"dqxclarity - running (v{version})";
    }

    private void OnLogLine(LogLine line) =>
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            Lines.Add(line);
            while (Lines.Count > MaxLines)
                Lines.RemoveAt(0);
            OnPropertyChanged(nameof(HasNoLines));
        });

    // Surfaces a status message into the log view from the translation runtime.
    public void AppendLine(string text, string level = "info") =>
        OnLogLine(new LogLine { Level = level, Text = text });

    [RelayCommand]
    private void Stop()
    {
        StopRequested?.Invoke();
        NavigateBack?.Invoke();
    }

    [RelayCommand]
    private void Back() => NavigateBack?.Invoke();

    [RelayCommand]
    private void DismissStopWarning() => ShowStopWarning = false;

    public void Reset()
    {
        Lines.Clear();
        ExitedWithError = false;
        HasExited = false;
        StatusTitle = "dqxclarity - running";
        ActiveLogTab = "dqxclarity";
        OnPropertyChanged(nameof(HasNoLines));
    }

    // There's no separate translation process to gate window-close on anymore;
    // the runtime lives in-process and is torn down with the app.
    public bool TryClose() => true;
}
