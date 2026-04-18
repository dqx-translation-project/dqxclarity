using Avalonia.Controls;
using Avalonia.Interactivity;

namespace DqxClarity.Launcher.Views;

public partial class ConfirmDialog : UserControl
{
    public event Action<bool>? RequestClose;

    public ConfirmDialog(string title, string body,
        string cancelLabel = "Cancel", string confirmLabel = "OK",
        bool confirmIsDanger = false)
    {
        InitializeComponent();
        TitleText.Text    = title;
        BodyText.Text     = body;
        CancelBtn.Content = cancelLabel;
        OkBtn.Content     = confirmLabel;
        if (confirmIsDanger)
        {
            OkBtn.Classes.Remove("accent");
            OkBtn.Classes.Add("danger");
        }
    }

    private void OnOk(object? sender, RoutedEventArgs e)     => RequestClose?.Invoke(true);
    private void OnCancel(object? sender, RoutedEventArgs e) => RequestClose?.Invoke(false);
}
