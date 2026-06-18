using Avalonia.Controls;
using Avalonia.Interactivity;

namespace DqxClarity.Launcher.Views;

public partial class SupportPopup : UserControl
{
    public event Action? RequestClose;
    public event Action<string>? RequestOpenUrl;

    public SupportPopup()
    {
        InitializeComponent();
    }

    private void OnGithubClick(object? sender, RoutedEventArgs e) =>
        RequestOpenUrl?.Invoke("https://github.com/dqx-translation-project/dqxclarity/issues");

    private void OnClose(object? sender, RoutedEventArgs e) => RequestClose?.Invoke();
}
