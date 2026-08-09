using System.Collections.Specialized;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using DqxClarity.ViewModels;

namespace DqxClarity.Views;

public partial class DebugView : UserControl
{
    private DebugViewModel? _vm;

    public DebugView()
    {
        InitializeComponent();
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm != null)
            _vm.VisibleEntries.CollectionChanged -= OnEntriesChanged;
        if (DataContext is not DebugViewModel vm) return;
        _vm = vm;
        vm.VisibleEntries.CollectionChanged += OnEntriesChanged;
    }

    private string _typeBuffer = "";
    private DateTime _lastKeyTime = DateTime.MinValue;
    private const double TypeResetMs = 800;

    private void OnFilterKeyDown(object? sender, KeyEventArgs e)
    {
        if (_vm == null) return;

        if (e.Key == Key.Back)
        {
            if (_typeBuffer.Length > 0) _typeBuffer = _typeBuffer[..^1];
        }
        else if (e.KeySymbol is { Length: 1 } sym)
        {
            var now = DateTime.Now;
            if ((now - _lastKeyTime).TotalMilliseconds > TypeResetMs) _typeBuffer = "";
            _lastKeyTime = now;
            _typeBuffer += sym;
        }
        else return;

        if (string.IsNullOrEmpty(_typeBuffer)) return;
        var match = _vm.Filters.FirstOrDefault(
            f => f.StartsWith(_typeBuffer, StringComparison.OrdinalIgnoreCase));
        if (match != null) _vm.SelectedFilter = match;
    }

    private void OnEntriesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Dispatcher.UIThread.Post(() => DebugScroll.ScrollToEnd(), DispatcherPriority.Background);
    }

    private async void OnCopyClick(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: DebugPacketEntry entry }) return;
        var text = entry.WasModified
            ? $"[{entry.Timestamp:HH:mm:ss.fff}] {entry.TypeName} [modified]\n\nOriginal:\n{entry.HexDump}\n\nModified:\n{entry.ModifiedHexDump}"
            : $"[{entry.Timestamp:HH:mm:ss.fff}] {entry.TypeName}\n\n{entry.HexDump}";
        await CopyToClipboard(text);
    }

    private async void OnCopyOriginalClick(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: DebugPacketEntry entry }) return;
        await CopyToClipboard(entry.HexDump);
    }

    private async void OnCopyModifiedClick(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: DebugPacketEntry entry }) return;
        await CopyToClipboard(entry.ModifiedHexDump ?? "");
    }

    private static async Task CopyToClipboard(string text)
    {
        var clipboard = (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)
            ?.MainWindow?.Clipboard;
        if (clipboard != null)
            await clipboard.SetTextAsync(text);
    }
}
