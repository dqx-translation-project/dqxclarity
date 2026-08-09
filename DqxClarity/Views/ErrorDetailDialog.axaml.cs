using Avalonia.Controls;
using Avalonia.Interactivity;

namespace DqxClarity.Views;

public partial class ErrorDetailDialog : UserControl
{
    private readonly string _detail;

    public event Action? RequestClose;

    public ErrorDetailDialog(string detail)
    {
        InitializeComponent();
        _detail = detail;
        DetailBox.Text = detail;
    }

    private async void OnCopyAll(object? sender, RoutedEventArgs e)
    {
        var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
        if (clipboard != null)
            await clipboard.SetTextAsync(_detail);
    }

    private void OnClose(object? sender, RoutedEventArgs e) => RequestClose?.Invoke();
}
