using System.Collections.ObjectModel;
using Avalonia.Input.Platform;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace DqxClarity.Launcher.ViewModels;

public partial class Text2ClipboardViewModel : ObservableObject
{
    private readonly IClipboard? _clipboard;

    [ObservableProperty] private string _preview = "";
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private string? _selectedQuestKey;

    public IReadOnlyList<string> QuestKeys { get; }
    public IReadOnlyList<KeyValuePair<string, string>> CommonPhrases { get; }

    public Text2ClipboardViewModel(IClipboard? clipboard)
    {
        _clipboard = clipboard;
        QuestKeys = new ReadOnlyCollection<string>(Services.Text2ClipboardStrings.Quests.Keys.ToList());
        CommonPhrases = new ReadOnlyCollection<KeyValuePair<string, string>>(Services.Text2ClipboardStrings.CommonPhrases.ToList());
    }

    partial void OnSelectedQuestKeyChanged(string? value)
    {
        CopySelectedQuestCommand.NotifyCanExecuteChanged();
        if (value == null || !Services.Text2ClipboardStrings.Quests.TryGetValue(value, out var text)) return;
        Preview = text;
        _ = CopyToClipboard(text);
    }

    [RelayCommand(CanExecute = nameof(CanCopyQuest))]
    private async Task CopySelectedQuest()
    {
        if (SelectedQuestKey == null) return;
        await CopyToClipboard(Services.Text2ClipboardStrings.Quests[SelectedQuestKey]);
    }

    [RelayCommand]
    private async Task CopyPhrase(string phraseKey)
    {
        if (!Services.Text2ClipboardStrings.CommonPhrases.TryGetValue(phraseKey, out var phrase)) return;
        await CopyToClipboard(phrase);
    }

    private bool CanCopyQuest() => !string.IsNullOrEmpty(SelectedQuestKey);

    private async Task CopyToClipboard(string text)
    {
        if (_clipboard == null)
        {
            Status = "Clipboard not available.";
            return;
        }
        await _clipboard.SetTextAsync(text);
        Status = "Copied to clipboard.";
        await Task.Delay(1000);
        Status = "";
    }
}
