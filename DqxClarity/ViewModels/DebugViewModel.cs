using System.Collections.ObjectModel;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace DqxClarity.ViewModels;

public partial class DebugViewModel : ObservableObject
{
    private const int MaxEntriesPerType = 100;

    [ObservableProperty] private string? _selectedFilter;

    public ObservableCollection<string> Filters { get; } = [];
    public ObservableCollection<DebugPacketEntry> VisibleEntries { get; } = [];

    private readonly Dictionary<string, List<DebugPacketEntry>> _entriesByType = [];
    private readonly HashSet<string> _seenTypes = [];

    partial void OnSelectedFilterChanged(string? value) => RebuildVisible();

    public void AddPacket(string typeName, int rawLength, string hexDump, int modifiedLength, string? modifiedHexDump)
    {
        var entry = new DebugPacketEntry
        {
            TypeName = typeName,
            ByteLength = rawLength,
            HexDump = hexDump,
            ModifiedHexDump = modifiedHexDump,
            ModifiedByteLength = modifiedLength,
            WasModified = modifiedHexDump != null,
            Timestamp = DateTime.Now,
        };

        if (!_entriesByType.TryGetValue(typeName, out var list))
        {
            list = [];
            _entriesByType[typeName] = list;
        }
        list.Add(entry);
        if (list.Count > MaxEntriesPerType)
            list.RemoveAt(0);

        if (_seenTypes.Add(typeName))
        {
            var inserted = false;
            for (int i = 0; i < Filters.Count; i++)
            {
                if (string.Compare(typeName, Filters[i], StringComparison.Ordinal) < 0)
                {
                    Filters.Insert(i, typeName);
                    inserted = true;
                    break;
                }
            }
            if (!inserted) Filters.Add(typeName);

            if (SelectedFilter == null)
                SelectedFilter = typeName;
        }

        if (SelectedFilter == typeName)
        {
            VisibleEntries.Add(entry);
            while (VisibleEntries.Count > MaxEntriesPerType)
                VisibleEntries.RemoveAt(0);
        }
    }

    [RelayCommand]
    private void Clear()
    {
        if (SelectedFilter == null) return;

        _entriesByType.Remove(SelectedFilter);
        _seenTypes.Remove(SelectedFilter);
        Filters.Remove(SelectedFilter);
        VisibleEntries.Clear();

        SelectedFilter = Filters.Count > 0 ? Filters[0] : null;
    }

    [RelayCommand]
    private void ClearAll()
    {
        _entriesByType.Clear();
        _seenTypes.Clear();
        Filters.Clear();
        VisibleEntries.Clear();
        SelectedFilter = null;
    }

    [RelayCommand]
    private async Task CopyEntry(DebugPacketEntry? entry)
    {
        if (entry == null) return;
        var text = entry.WasModified
            ? $"[{entry.Timestamp:HH:mm:ss.fff}] {entry.TypeName} [modified]\n\nOriginal:\n{entry.HexDump}\n\nModified:\n{entry.ModifiedHexDump}"
            : $"[{entry.Timestamp:HH:mm:ss.fff}] {entry.TypeName}\n\n{entry.HexDump}";
        var clipboard = (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)
            ?.MainWindow?.Clipboard;
        if (clipboard != null)
            await clipboard.SetTextAsync(text);
    }

    private void RebuildVisible()
    {
        VisibleEntries.Clear();
        if (SelectedFilter == null) return;
        var source = _entriesByType.GetValueOrDefault(SelectedFilter) ?? [];
        foreach (var e in source)
            VisibleEntries.Add(e);
    }
}

public class DebugPacketEntry
{
    public string TypeName { get; init; } = "";
    public int ByteLength { get; init; }
    public string HexDump { get; init; } = "";
    public string? ModifiedHexDump { get; init; }
    public int ModifiedByteLength { get; init; }
    public bool WasModified { get; init; }
    public DateTime Timestamp { get; init; }
}
