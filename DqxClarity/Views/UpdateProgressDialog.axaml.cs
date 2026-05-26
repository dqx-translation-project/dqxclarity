using Avalonia.Controls;

namespace DqxClarity.Views;

public partial class UpdateProgressDialog : UserControl
{
    public UpdateProgressDialog() => InitializeComponent();

    public void UpdateProgress(long received, long total)
    {
        if (total <= 0)
        {
            ProgressBar.IsIndeterminate = true;
            StatusText.Text = $"{FormatBytes(received)} downloaded...";
        }
        else
        {
            var pct = (double)received / total * 100.0;
            ProgressBar.IsIndeterminate = false;
            ProgressBar.Value = pct;
            StatusText.Text = $"{FormatBytes(received)} / {FormatBytes(total)}  ({pct:F0}%)";
        }
    }

    private static string FormatBytes(long bytes) =>
        bytes < 1024 * 1024
            ? $"{bytes / 1024.0:F1} KB"
            : $"{bytes / (1024.0 * 1024):F1} MB";
}
