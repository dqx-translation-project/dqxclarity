using System.Text;
using System.Text.RegularExpressions;
using Avalonia.Controls;
using Avalonia.Interactivity;
using DqxClarity.Launcher.Models;

namespace DqxClarity.Launcher.Views;

public partial class UpdateDialog : UserControl
{
    public event Action<bool>? RequestClose;

    public UpdateDialog(UpdateInfo info)
    {
        InitializeComponent();
        HeaderText.Text = $"Update available — {info.Version}";
        BodyText.Text   = CleanMarkdown(info.Body);
    }

    private static string CleanMarkdown(string md)
    {
        if (string.IsNullOrEmpty(md)) return md;
        var sb = new StringBuilder();
        foreach (var raw in md.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith("### "))
                line = line[4..].Trim().ToUpperInvariant();
            else if (line.StartsWith("## "))
                line = line[3..].Trim().ToUpperInvariant();
            else if (line.StartsWith("# "))
                line = line[2..].Trim().ToUpperInvariant();
            else if (line.StartsWith("- ") || line.StartsWith("* "))
                line = "• " + line[2..];
            line = Regex.Replace(line, @"\*\*(.+?)\*\*", "$1");
            line = Regex.Replace(line, @"\*(.+?)\*",     "$1");
            line = Regex.Replace(line, @"`(.+?)`",       "$1");
            sb.AppendLine(line);
        }
        return sb.ToString().TrimEnd();
    }

    private void OnUpdate(object? sender, RoutedEventArgs e) => RequestClose?.Invoke(true);
    private void OnLater(object? sender, RoutedEventArgs e)  => RequestClose?.Invoke(false);
}
