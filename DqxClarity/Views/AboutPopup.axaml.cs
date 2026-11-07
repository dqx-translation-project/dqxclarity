using Avalonia.Controls;
using Avalonia.Interactivity;

namespace DqxClarity.Views;

public partial class AboutPopup : UserControl
{
    public event Action? RequestClose;
    public event Action<string>? RequestOpenUrl;

    public AboutPopup()
    {
        InitializeComponent();
    }

    private void OnKofiClick(object? sender, RoutedEventArgs e) =>
        RequestOpenUrl?.Invoke("https://ko-fi.com/serany");

    private void OnClose(object? sender, RoutedEventArgs e) => RequestClose?.Invoke();
}
