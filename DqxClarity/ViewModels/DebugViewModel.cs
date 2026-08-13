using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace DqxClarity.ViewModels;

public partial class DebugViewModel : ObservableObject
{
    private const int MaxEntriesPerType = 100;

    [ObservableProperty] private string? _selectedFilter;
    [ObservableProperty] private string _byteFilter = "";

    // Filters: every distinct packet type name ever seen (master list; unaffected
    // by ByteFilter). FilterOptions: the subset of Filters that currently has at
    // least one entry matching ByteFilter -- this is what the ComboBox actually
    // shows. They're identical whenever ByteFilter is empty.
    public ObservableCollection<string> Filters { get; } = [];
    public ObservableCollection<string> FilterOptions { get; } = [];
    public ObservableCollection<DebugPacketEntry> VisibleEntries { get; } = [];

    private readonly Dictionary<string, List<DebugPacketEntry>> _entriesByType = [];
    private readonly HashSet<string> _seenTypes = [];
    private byte[]? _byteFilterPattern;

    partial void OnSelectedFilterChanged(string? value) => RebuildVisible();

    partial void OnByteFilterChanged(string value)
    {
        _byteFilterPattern = ParseBytePattern(value);
        RebuildFilterOptions();
    }

    public void AddPacket(string typeName, byte[] rawBytes, string hexDump, byte[]? modifiedBytes, string? modifiedHexDump)
    {
        var entry = new DebugPacketEntry
        {
            TypeName = typeName,
            RawBytes = rawBytes,
            ByteLength = rawBytes.Length,
            HexDump = hexDump,
            ModifiedBytes = modifiedBytes,
            ModifiedHexDump = modifiedHexDump,
            ModifiedByteLength = modifiedBytes?.Length ?? 0,
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
            InsertSorted(Filters, typeName);

        // Either this type is new, or it's this type's first entry to match an
        // active byte filter -- either way it needs to show up in the dropdown.
        var entryMatches = EntryMatchesByteFilter(entry);
        if (entryMatches && !FilterOptions.Contains(typeName))
            InsertSorted(FilterOptions, typeName);

        if (SelectedFilter == null && entryMatches)
            SelectedFilter = typeName;

        if (SelectedFilter == typeName && entryMatches)
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
        FilterOptions.Remove(SelectedFilter);
        VisibleEntries.Clear();

        SelectedFilter = FilterOptions.Count > 0 ? FilterOptions[0] : null;
    }

    [RelayCommand]
    private void ClearAll()
    {
        _entriesByType.Clear();
        _seenTypes.Clear();
        Filters.Clear();
        FilterOptions.Clear();
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
            if (EntryMatchesByteFilter(e))
                VisibleEntries.Add(e);
    }

    // Recomputes which types have at least one byte-filter match (cheap: bounded
    // by MaxEntriesPerType per type, and only runs per keystroke on ByteFilter,
    // not per incoming packet -- see AddPacket for the cheap incremental path).
    private void RebuildFilterOptions()
    {
        FilterOptions.Clear();
        foreach (var name in Filters) // Filters is already sorted; append preserves order
            if (TypeMatchesByteFilter(name))
                FilterOptions.Add(name);

        if (SelectedFilter != null && !FilterOptions.Contains(SelectedFilter))
            SelectedFilter = FilterOptions.Count > 0 ? FilterOptions[0] : null;
        else
            RebuildVisible(); // selection didn't move, but which of its entries show might have
    }

    private bool TypeMatchesByteFilter(string typeName)
    {
        if (_byteFilterPattern == null) return true;
        return _entriesByType.TryGetValue(typeName, out var list) && list.Any(EntryMatchesByteFilter);
    }

    private bool EntryMatchesByteFilter(DebugPacketEntry entry)
    {
        if (_byteFilterPattern == null) return true;
        if (ContainsSequence(entry.RawBytes, _byteFilterPattern)) return true;
        return entry.ModifiedBytes != null && ContainsSequence(entry.ModifiedBytes, _byteFilterPattern);
    }

    // Plain byte-sequence substring search. Packets here top out around a few KB
    // and filter patterns are short, so the naive O(n*m) scan is plenty fast --
    // no need for Boyer-Moore or similar for a debug tool.
    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0) return true;
        if (needle.Length > haystack.Length) return false;
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    // Accepts space/comma-separated hex byte pairs ("E3 81 95 E3 81 99"), an
    // unbroken hex run ("E3819581 99"), and tolerates "0x"/"0X" prefixes.
    // Anything that doesn't resolve to a clean whole number of bytes is treated
    // as "no filter" rather than guessing at a partial match.
    private static byte[]? ParseBytePattern(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        var withoutPrefixes = text.Replace("0x", "", StringComparison.OrdinalIgnoreCase);
        var hexOnly = new string(withoutPrefixes.Where(Uri.IsHexDigit).ToArray());
        if (hexOnly.Length == 0 || hexOnly.Length % 2 != 0) return null;

        var bytes = new byte[hexOnly.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            if (!byte.TryParse(hexOnly.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[i]))
                return null;
        }
        return bytes;
    }

    private static void InsertSorted(ObservableCollection<string> collection, string value)
    {
        for (var i = 0; i < collection.Count; i++)
        {
            if (string.Compare(value, collection[i], StringComparison.Ordinal) < 0)
            {
                collection.Insert(i, value);
                return;
            }
        }
        collection.Add(value);
    }
}

public class DebugPacketEntry
{
    public string TypeName { get; init; } = "";
    public byte[] RawBytes { get; init; } = [];
    public int ByteLength { get; init; }
    public string HexDump { get; init; } = "";
    public byte[]? ModifiedBytes { get; init; }
    public string? ModifiedHexDump { get; init; }
    public int ModifiedByteLength { get; init; }
    public bool WasModified { get; init; }
    public DateTime Timestamp { get; init; }
}
