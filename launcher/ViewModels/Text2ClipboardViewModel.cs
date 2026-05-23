using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Text.Encodings.Web;
using System.Text.Json;
using Avalonia.Input.Platform;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DqxClarity.Launcher.Services;

namespace DqxClarity.Launcher.ViewModels;

public class PhraseEntry
{
    public string Identifier { get; init; } = "";
    public string Japanese { get; init; } = "";
    public bool IsCustom { get; init; }
    public bool IsDivider { get; init; }
}

public class PinnedEntry
{
    public string Identifier { get; init; } = "";
    public string Japanese { get; init; } = "";
    public string TooltipText => $"{Identifier} ({Japanese})";
}

public partial class Text2ClipboardViewModel : ObservableObject
{
    public const int MaxPins = 20;

    private readonly IClipboard? _clipboard;
    private readonly ConfigService? _cfg;

    [ObservableProperty] private string _preview = "";
    [ObservableProperty] private string _questStatus = "";
    [ObservableProperty] private string _phrasesStatus = "";
    [ObservableProperty] private string? _selectedQuestKey;

    private int _questStatusToken;
    private int _phrasesStatusToken;

    [ObservableProperty] private PhraseEntry? _selectedPhrase;
    [ObservableProperty] private string _phrasesSaveError = "";

    [ObservableProperty] private string _newIdentifier = "";
    [ObservableProperty] private string _newJapanese = "";

    public IReadOnlyList<string> QuestKeys { get; }
    public ObservableCollection<string> PinnedIdentifiers { get; } = new();
    public ObservableCollection<PinnedEntry> PinnedButtons { get; } = new();
    public ObservableCollection<PhraseEntry> DropdownItems { get; } = new();

    private readonly List<(string Identifier, string Japanese)> _savedCustomPhrases = new();

    public Text2ClipboardViewModel(IClipboard? clipboard, ConfigService? cfg = null)
    {
        _clipboard = clipboard;
        _cfg = cfg;
        QuestKeys = new ReadOnlyCollection<string>(Services.Text2ClipboardStrings.Quests.Keys.ToList());

        PinnedIdentifiers.CollectionChanged += OnPinnedChanged;

        LoadUserPhrases();
        RebuildDropdown();
    }

    private void OnPinnedChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action == NotifyCollectionChangedAction.Replace
            && e.NewStartingIndex >= 0 && e.NewStartingIndex < PinnedButtons.Count
            && e.NewItems?[0] is string newId)
        {
            var jp = LookupJapanese(newId) ?? "";
            PinnedButtons[e.NewStartingIndex] = new PinnedEntry { Identifier = newId, Japanese = jp };
        }
        else
        {
            RebuildPinnedButtons();
        }
        OnPropertyChanged(nameof(HasPins));
        OnPropertyChanged(nameof(PinButtonLabel));
        PinToggleCommand.NotifyCanExecuteChanged();
    }

    public void ReorderPin(string sourceId, string targetId)
    {
        if (string.IsNullOrEmpty(sourceId) || string.IsNullOrEmpty(targetId)) return;
        if (sourceId == targetId) return;
        var sourceIdx = PinnedIdentifiers.IndexOf(sourceId);
        var targetIdx = PinnedIdentifiers.IndexOf(targetId);
        if (sourceIdx < 0 || targetIdx < 0) return;
        // Swap (not shift): source and target trade positions; everything else stays put.
        var src = PinnedIdentifiers[sourceIdx];
        PinnedIdentifiers[sourceIdx] = PinnedIdentifiers[targetIdx];
        PinnedIdentifiers[targetIdx] = src;
        try { PersistToDisk(); }
        catch (Exception ex) { PhrasesSaveError = $"Save failed: {ex.Message}"; }
    }

    private void RebuildPinnedButtons()
    {
        PinnedButtons.Clear();
        foreach (var id in PinnedIdentifiers)
        {
            var jp = LookupJapanese(id);
            if (jp == null) continue;
            PinnedButtons.Add(new PinnedEntry { Identifier = id, Japanese = jp });
        }
    }

    private string? LookupJapanese(string identifier)
    {
        var custom = _savedCustomPhrases.FirstOrDefault(p => p.Identifier == identifier);
        if (custom.Identifier != null && custom.Japanese != null && custom.Identifier == identifier)
            return custom.Japanese;
        return Services.Text2ClipboardStrings.CommonPhrases.TryGetValue(identifier, out var jp) ? jp : null;
    }

    public bool HasPins => PinnedIdentifiers.Count > 0;

    public string PinButtonLabel
    {
        get
        {
            if (SelectedPhrase == null || SelectedPhrase.IsDivider) return "Pin";
            return PinnedIdentifiers.Contains(SelectedPhrase.Identifier) ? "Unpin" : "Pin";
        }
    }

    private void LoadUserPhrases()
    {
        if (_cfg == null) return;
        var raw = _cfg.ReadUserPhrases();
        if (string.IsNullOrWhiteSpace(raw)) return;
        try
        {
            using var doc = JsonDocument.Parse(raw);

            if (doc.RootElement.TryGetProperty("custom_phrases", out var customs)
                && customs.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in customs.EnumerateArray())
                {
                    var id = el.TryGetProperty("identifier", out var i) ? i.GetString() ?? "" : "";
                    var jp = el.TryGetProperty("japanese", out var j) ? j.GetString() ?? "" : "";
                    if (!string.IsNullOrWhiteSpace(id) && !string.IsNullOrWhiteSpace(jp)
                        && !Services.Text2ClipboardStrings.CommonPhrases.ContainsKey(id)
                        && !_savedCustomPhrases.Any(p => p.Identifier == id))
                    {
                        _savedCustomPhrases.Add((id, jp));
                    }
                }
            }

            if (doc.RootElement.TryGetProperty("pinned", out var pinned)
                && pinned.ValueKind == JsonValueKind.Array)
            {
                var validIds = new HashSet<string>(
                    _savedCustomPhrases.Select(p => p.Identifier)
                        .Concat(Services.Text2ClipboardStrings.CommonPhrases.Keys));
                foreach (var el in pinned.EnumerateArray())
                {
                    var id = el.GetString() ?? "";
                    if (string.IsNullOrWhiteSpace(id)) continue;
                    if (!validIds.Contains(id)) continue;
                    if (PinnedIdentifiers.Contains(id)) continue;
                    PinnedIdentifiers.Add(id);
                    if (PinnedIdentifiers.Count >= MaxPins) break;
                }
            }
        }
        catch { /* corrupt file - start empty */ }
    }

    private void RebuildDropdown()
    {
        var prevId = SelectedPhrase?.Identifier;
        var prevWasDivider = SelectedPhrase?.IsDivider ?? false;

        DropdownItems.Clear();

        var customsSorted = _savedCustomPhrases
            .OrderBy(p => p.Identifier, StringComparer.OrdinalIgnoreCase)
            .ToList();
        foreach (var (id, jp) in customsSorted)
            DropdownItems.Add(new PhraseEntry { Identifier = id, Japanese = jp, IsCustom = true });

        var preconfigured = Services.Text2ClipboardStrings.CommonPhrases
            .OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (customsSorted.Count > 0 && preconfigured.Count > 0)
            DropdownItems.Add(new PhraseEntry { IsDivider = true, Identifier = "──────────" });

        foreach (var kv in preconfigured)
            DropdownItems.Add(new PhraseEntry { Identifier = kv.Key, Japanese = kv.Value, IsCustom = false });

        if (prevId != null && !prevWasDivider)
            SelectedPhrase = DropdownItems.FirstOrDefault(e => !e.IsDivider && e.Identifier == prevId);

        PinToggleCommand.NotifyCanExecuteChanged();
        DeleteCustomCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(PinButtonLabel));
    }

    partial void OnSelectedQuestKeyChanged(string? value)
    {
        if (value == null || !Services.Text2ClipboardStrings.Quests.TryGetValue(value, out var text)) return;
        Preview = FormatQuestPreview(text);
        _ = CopyToClipboard(text, forQuest: true);
    }

    private static string FormatQuestPreview(string text)
    {
        // Game text is never more than 2 lines; cap at 10 chars per line, 20 chars total.
        const int perLine = 10;
        const int maxLines = 2;
        var trimmed = text.Length > perLine * maxLines ? text.Substring(0, perLine * maxLines) : text;
        if (trimmed.Length <= perLine) return trimmed;
        return trimmed.Substring(0, perLine) + "\n" + trimmed.Substring(perLine);
    }

    partial void OnSelectedPhraseChanged(PhraseEntry? value)
    {
        PinToggleCommand.NotifyCanExecuteChanged();
        DeleteCustomCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(PinButtonLabel));

        if (value == null) return;
        if (value.IsDivider)
        {
            SelectedPhrase = null;
            return;
        }
        _ = CopyToClipboard(value.Japanese, forQuest: false);
    }

    [RelayCommand]
    private void SelectPin(string? identifier)
    {
        if (string.IsNullOrEmpty(identifier)) return;
        var entry = DropdownItems.FirstOrDefault(e => !e.IsDivider && e.Identifier == identifier);
        if (entry == null) return;

        if (ReferenceEquals(SelectedPhrase, entry))
        {
            _ = CopyToClipboard(entry.Japanese, forQuest: false);
        }
        else
        {
            SelectedPhrase = entry;
        }
    }

    [RelayCommand]
    private void AddCustomPhrase()
    {
        PhrasesSaveError = "";
        var id = (NewIdentifier ?? "").Trim();
        var jp = (NewJapanese ?? "").Trim();

        if (id.Length == 0 || jp.Length == 0)
        {
            PhrasesSaveError = "Both Identifier and Japanese are required.";
            return;
        }
        if (Services.Text2ClipboardStrings.CommonPhrases.ContainsKey(id))
        {
            PhrasesSaveError = $"Identifier '{id}' already exists in preconfigured phrases.";
            return;
        }
        if (_savedCustomPhrases.Any(p => p.Identifier == id))
        {
            PhrasesSaveError = $"Identifier '{id}' is already a custom phrase.";
            return;
        }

        _savedCustomPhrases.Add((id, jp));
        try { PersistToDisk(); }
        catch (Exception ex) { PhrasesSaveError = $"Save failed: {ex.Message}"; return; }

        RebuildDropdown();
        NewIdentifier = "";
        NewJapanese = "";
    }

    [RelayCommand(CanExecute = nameof(CanDeleteCustom))]
    private void DeleteCustom()
    {
        if (SelectedPhrase == null || !SelectedPhrase.IsCustom) return;
        var id = SelectedPhrase.Identifier;

        _savedCustomPhrases.RemoveAll(p => p.Identifier == id);
        for (int i = PinnedIdentifiers.Count - 1; i >= 0; i--)
            if (PinnedIdentifiers[i] == id) PinnedIdentifiers.RemoveAt(i);

        try { PersistToDisk(); }
        catch (Exception ex) { PhrasesSaveError = $"Save failed: {ex.Message}"; }

        SelectedPhrase = null;
        RebuildDropdown();
    }

    private bool CanDeleteCustom() => SelectedPhrase != null && SelectedPhrase.IsCustom;

    [RelayCommand(CanExecute = nameof(CanPinToggle))]
    private void PinToggle()
    {
        if (SelectedPhrase == null || SelectedPhrase.IsDivider) return;
        var id = SelectedPhrase.Identifier;
        if (PinnedIdentifiers.Contains(id))
        {
            PinnedIdentifiers.Remove(id);
        }
        else
        {
            if (PinnedIdentifiers.Count >= MaxPins) return;
            PinnedIdentifiers.Add(id);
        }

        try { PersistToDisk(); }
        catch (Exception ex) { PhrasesSaveError = $"Save failed: {ex.Message}"; }
    }

    private bool CanPinToggle()
    {
        if (SelectedPhrase == null || SelectedPhrase.IsDivider) return false;
        if (!PinnedIdentifiers.Contains(SelectedPhrase.Identifier) && PinnedIdentifiers.Count >= MaxPins)
            return false;
        return true;
    }

    private void PersistToDisk()
    {
        if (_cfg == null) return;
        var json = JsonSerializer.Serialize(
            new
            {
                custom_phrases = _savedCustomPhrases
                    .Select(p => new { identifier = p.Identifier, japanese = p.Japanese })
                    .ToList(),
                pinned = PinnedIdentifiers.ToList(),
            },
            new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            });
        _cfg.SaveUserPhrases(json);
    }

    private async Task CopyToClipboard(string text, bool forQuest)
    {
        if (_clipboard == null)
        {
            SetCopyStatus("Clipboard not available.", forQuest);
            return;
        }
        await _clipboard.SetTextAsync(text);
        SetCopyStatus("Copied to clipboard.", forQuest);
    }

    private void SetCopyStatus(string message, bool forQuest)
    {
        if (forQuest)
        {
            QuestStatus = message;
            var token = ++_questStatusToken;
            _ = Task.Delay(1000).ContinueWith(_ =>
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    if (token == _questStatusToken) QuestStatus = "";
                }));
        }
        else
        {
            PhrasesStatus = message;
            var token = ++_phrasesStatusToken;
            _ = Task.Delay(1000).ContinueWith(_ =>
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    if (token == _phrasesStatusToken) PhrasesStatus = "";
                }));
        }
    }
}
