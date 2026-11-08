using Avalonia.Controls;
using Avalonia.Interactivity;

namespace DqxClarity.Views;

public partial class InfoDialog : UserControl
{
    public event Action? RequestClose;

    public InfoDialog(string title, string body)
    {
        InitializeComponent();
        TitleText.Text = title;
        BodyText.Text  = body;
    }

    private void OnOk(object? sender, RoutedEventArgs e) => RequestClose?.Invoke();
}
