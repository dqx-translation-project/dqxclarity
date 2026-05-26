using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;

namespace DqxClarity.Views;

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
    private void OnInputKeyDown(object? sender, KeyEventArgs e) { if (e.Key == Key.Enter) RequestClose?.Invoke(InputBox.Text); }
}
