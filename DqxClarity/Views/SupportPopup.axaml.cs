using Avalonia.Controls;
using Avalonia.Interactivity;

namespace DqxClarity.Views;

public partial class SupportPopup : UserControl
{
    public event Action? RequestClose;
    private bool _copied;

    public SupportPopup()
    {
        InitializeComponent();
    }

    private async void OnCopy(object? sender, RoutedEventArgs e)
    {
        if (_copied) return;
        var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
        if (clipboard == null) return;
        await clipboard.SetTextAsync("https://discord.gg/dragonquestx");
        _copied = true;
        CopyBtn.Content = "Copied!";
        await Task.Delay(2000);
        _copied = false;
        CopyBtn.Content = "Copy";
    }

    private void OnClose(object? sender, RoutedEventArgs e) => RequestClose?.Invoke();
}
