using Avalonia.Controls;
using Avalonia.Interactivity;

namespace DqxClarity.Launcher.Views;

public partial class InputDialog : UserControl
{
    public event Action<string?>? RequestClose;

    public InputDialog(string title, string prompt, bool isPassword = false)
    {
        InitializeComponent();
        TitleText.Text  = title;
        PromptText.Text = prompt;
        if (isPassword) InputBox.PasswordChar = '●';
    }

    private void OnOk(object? sender, RoutedEventArgs e)     => RequestClose?.Invoke(InputBox.Text);
    private void OnCancel(object? sender, RoutedEventArgs e) => RequestClose?.Invoke(null);
}
