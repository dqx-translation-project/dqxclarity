using Avalonia.Controls;
using Avalonia.Interactivity;

namespace DqxClarity.Views;

public partial class WelcomeDialog : UserControl
{
    public event Action? RequestClose;

    public WelcomeDialog() => InitializeComponent();

    private void OnOk(object? sender, RoutedEventArgs e)
    {
        if (AgreementCheck.IsChecked != true) return;
        RequestClose?.Invoke();
    }
}
