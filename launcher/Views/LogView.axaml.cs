using System.Collections.Specialized;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Media;
using Avalonia.Threading;
using DqxClarity.Launcher.Models;
using DqxClarity.Launcher.ViewModels;

namespace DqxClarity.Launcher.Views;

public partial class LogView : UserControl
{
    private LogViewModel? _vm;

    private static readonly FontFamily LogFont =
        new("Cascadia Code,Consolas,Courier New,monospace");

    public LogView()
    {
        InitializeComponent();
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (DataContext is not LogViewModel vm) return;
        _vm = vm;
        vm.Lines.CollectionChanged += OnLinesChanged;
    }

    private void OnLinesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Dispatcher.UIThread.Post(() =>
        {
            switch (e.Action)
            {
                case NotifyCollectionChangedAction.Add:
                    if (e.NewItems != null)
                        foreach (LogLine line in e.NewItems)
                            LogStack.Children.Add(MakeLogBlock(line));
                    break;
                case NotifyCollectionChangedAction.Remove:
                    if (e.OldItems != null)
                        for (int i = 0; i < e.OldItems.Count; i++)
                            LogStack.Children.RemoveAt(e.OldStartingIndex);
                    break;
                case NotifyCollectionChangedAction.Reset:
                    LogStack.Children.Clear();
                    break;
            }
            LogScroll.ScrollToEnd();
        }, DispatcherPriority.Background);
    }

    private TextBlock MakeLogBlock(LogLine line)
    {
        var tb = new TextBlock
        {
            FontFamily   = LogFont,
            FontSize     = 11,
            LineHeight   = 16,
            TextWrapping = TextWrapping.WrapWithOverflow,
        };

        if (line.Runs.Count > 0)
        {
            foreach (var run in line.Runs)
            {
                var r = new Run { Text = run.Text };
                r.Foreground = run.HexColor != null && Color.TryParse(run.HexColor, out var c)
                    ? new SolidColorBrush(c)
                    : GetLevelBrush(line.Level);
                tb.Inlines!.Add(r);
            }
        }
        else
        {
            tb.Text       = line.Text;
            tb.Foreground = GetLevelBrush(line.Level);
        }

        return tb;
    }

    private static IBrush GetLevelBrush(string level)
    {
        var key = level == "error" ? "AppDanger" : "AppText";
        return Application.Current?.Resources[key] as IBrush ?? Brushes.White;
    }
}
