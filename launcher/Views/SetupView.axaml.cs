using Avalonia;
using Avalonia.Controls;
using DqxClarity.Launcher.ViewModels;

namespace DqxClarity.Launcher.Views;

public partial class SetupView : UserControl
{
    public SetupView()
    {
        InitializeComponent();
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);

        if (DataContext is SetupViewModel vm)
        {
            vm.PipLines.CollectionChanged += (_, _) =>
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(
                    () => PipScroll.Offset = PipScroll.Offset.WithY(double.MaxValue),
                    Avalonia.Threading.DispatcherPriority.Background);
            };

            vm.PropertyChanged += async (_, args) =>
            {
                if (args.PropertyName == nameof(SetupViewModel.ShowUacModal) && vm.ShowUacModal)
                {
                    var win = TopLevel.GetTopLevel(this) as MainWindow;
                    if (win != null)
                        await win.ShowUacAsync(() => vm.CloseUacCommand.Execute(null));
                }
            };

            vm.ShowDetailRequested += async detail =>
            {
                var win = TopLevel.GetTopLevel(this) as MainWindow;
                if (win != null)
                    await win.ShowErrorDetailAsync(detail);
            };
        }
    }
}
