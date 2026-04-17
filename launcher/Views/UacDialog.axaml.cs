using Avalonia.Controls;
using Avalonia.Interactivity;

namespace DqxClarity.Launcher.Views;

public partial class UacDialog : UserControl
{
    public event Action? RequestClose;

    public UacDialog() => InitializeComponent();

    private void OnOk(object? sender, RoutedEventArgs e) => RequestClose?.Invoke();
}
