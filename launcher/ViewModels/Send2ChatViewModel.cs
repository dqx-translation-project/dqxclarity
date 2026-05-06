using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace DqxClarity.Launcher.ViewModels;

public partial class Send2ChatViewModel : ObservableObject
{
    private readonly Services.Send2ChatMemoryService _memory;
    private readonly Services.Send2ChatInputService _input;

    [ObservableProperty] private string _freeText = "";
    [ObservableProperty] private string _preview = "";
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private bool _sending;
    [ObservableProperty] private string? _selectedQuestKey;

    public IReadOnlyList<string> QuestKeys { get; }
    public IReadOnlyList<KeyValuePair<string, string>> CommonPhrases { get; }

    public Send2ChatViewModel(Services.Send2ChatMemoryService memory, Services.Send2ChatInputService input)
    {
        _memory = memory;
        _input = input;
        QuestKeys = new ReadOnlyCollection<string>(Services.Send2ChatStrings.Quests.Keys.ToList());
        CommonPhrases = new ReadOnlyCollection<KeyValuePair<string, string>>(Services.Send2ChatStrings.CommonPhrases.ToList());
    }

    partial void OnSendingChanged(bool value)
    {
        SendFreeTextCommand.NotifyCanExecuteChanged();
        SendSelectedQuestCommand.NotifyCanExecuteChanged();
        SendPhraseCommand.NotifyCanExecuteChanged();
    }

    partial void OnSelectedQuestKeyChanged(string? value)
    {
        SendSelectedQuestCommand.NotifyCanExecuteChanged();
        if (value != null && Services.Send2ChatStrings.Quests.TryGetValue(value, out var text))
        {
            Preview = text;
        }
    }

    [RelayCommand(CanExecute = nameof(CanSend))]
    private async Task SendFreeText() => await SendAsync(FreeText);

    [RelayCommand(CanExecute = nameof(CanSendQuest))]
    private async Task SendSelectedQuest()
    {
        if (SelectedQuestKey == null) return;
        await SendAsync(Services.Send2ChatStrings.Quests[SelectedQuestKey]);
    }

    [RelayCommand(CanExecute = nameof(CanSend))]
    private async Task SendPhrase(string phraseKey)
    {
        if (!Services.Send2ChatStrings.CommonPhrases.TryGetValue(phraseKey, out var phrase)) return;
        await SendAsync(phrase);
    }

    private bool CanSend() => !Sending;
    private bool CanSendQuest() => !Sending && !string.IsNullOrEmpty(SelectedQuestKey);

    private async Task SendAsync(string text)
    {
        if (Sending) return;
        Sending = true;
        Status = "";

        try
        {
            var truncated = Services.Send2ChatMemoryService.TruncateToMaxChars(text);
            if (string.IsNullOrWhiteSpace(truncated))
            {
                Status = "Enter text to send.";
                return;
            }

            var attach = _memory.TryAttach(out var attachError);
            if (attach != Services.AttachResult.Ok)
            {
                Status = attachError;
                return;
            }

            // Resolve the chat buffer address BEFORE touching the window or sending any arrow keys.
            // If resolution fails, the game must be left untouched.
            if (!_memory.TryResolveBufferAddress(out var cursor, out var resolveError))
            {
                Status = $"{resolveError} Open the chat window first (default: Shift+Enter).";
                return;
            }

            if (!_input.ActivateDqxWindow(_memory.AttachedPid))
            {
                Status = "DQX window not found.";
                return;
            }

            // Per-character loop must match send_to_chat.ahk WriteToDQX exactly.
            for (var i = 0; i < truncated.Length; i++)
            {
                var ch = truncated[i];

                if (!_input.ActivateDqxWindow(_memory.AttachedPid))
                {
                    Status = "DQX window not found.";
                    return;
                }

                // For each character: arrow right 3 times (50ms between), then write the UTF-8 slot.
                if (!_input.SendArrow(true)) { Status = "Failed to inject keystrokes (Right)."; return; }
                await Task.Delay(50);
                if (!_input.SendArrow(true)) { Status = "Failed to inject keystrokes (Right)."; return; }
                await Task.Delay(50);
                if (!_input.SendArrow(true)) { Status = "Failed to inject keystrokes (Right)."; return; }
                await Task.Delay(50);

                if (!_memory.WriteAhkChatChar(ref cursor, ch, out var writeError))
                {
                    Status = writeError;
                    return;
                }

                if (i + 1 == Services.Send2ChatMemoryService.MaxChars)
                {
                    if (!_input.ActivateDqxWindow(_memory.AttachedPid))
                    {
                        Status = "DQX window not found.";
                        return;
                    }

                    if (!_input.SendArrow(false)) { Status = "Failed to inject keystrokes (Left)."; return; }
                    await Task.Delay(50);
                    if (!_input.SendArrow(true)) { Status = "Failed to inject keystrokes (Right)."; return; }
                    await Task.Delay(50);
                }
            }

            Status = $"Sent {truncated.Length} chars.";
        }
        catch (Exception ex)
        {
            Status = $"Failed to send: {ex.Message}";
        }
        finally
        {
            Sending = false;
        }
    }
}
