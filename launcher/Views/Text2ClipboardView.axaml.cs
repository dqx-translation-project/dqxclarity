using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using DqxClarity.Launcher.ViewModels;

namespace DqxClarity.Launcher.Views;

public partial class Text2ClipboardView : UserControl
{
    private const string DragFormat = "dqxclarity/pin-id";
    private const double DragThresholdSquared = 25; // ~5px

    private Button? _pressedButton;
    private Point _pressedPoint;
    private string? _pressedId;
    private bool _dragging;

    public Text2ClipboardView()
    {
        InitializeComponent();
        // Use Tunnel + handledEventsToo so we see the events before Button handles them.
        AddHandler(PointerPressedEvent,  OnPinPointerPressed,  RoutingStrategies.Tunnel, handledEventsToo: true);
        AddHandler(PointerMovedEvent,    OnPinPointerMoved,    RoutingStrategies.Tunnel, handledEventsToo: true);
        AddHandler(PointerReleasedEvent, OnPinPointerReleased, RoutingStrategies.Tunnel, handledEventsToo: true);
        AddHandler(DragDrop.DropEvent,     OnPinDrop,     handledEventsToo: true);
        AddHandler(DragDrop.DragOverEvent, OnPinDragOver, handledEventsToo: true);
    }

    private static Button? PinButtonFromSource(object? source)
    {
        Visual? v = source as Visual;
        while (v != null)
        {
            if (v is Button b && b.DataContext is PinnedEntry) return b;
            v = v.GetVisualParent();
        }
        return null;
    }

    private void OnPinPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        var btn = PinButtonFromSource(e.Source);
        if (btn == null) return;
        if (!e.GetCurrentPoint(btn).Properties.IsLeftButtonPressed) return;
        if (btn.DataContext is not PinnedEntry entry) return;

        _pressedButton = btn;
        _pressedPoint  = e.GetPosition(btn);
        _pressedId     = entry.Identifier;
        _dragging      = false;
    }

    private async void OnPinPointerMoved(object? sender, PointerEventArgs e)
    {
        if (_pressedButton == null || _pressedId == null || _dragging) return;

        var pos = e.GetPosition(_pressedButton);
        var dx = pos.X - _pressedPoint.X;
        var dy = pos.Y - _pressedPoint.Y;
        if (dx * dx + dy * dy < DragThresholdSquared) return;

        _dragging = true;
        var id = _pressedId;
        var data = new DataObject();
        data.Set(DragFormat, id);
        try
        {
            await DragDrop.DoDragDrop(e, data, DragDropEffects.Move);
        }
        finally
        {
            _pressedButton = null;
            _pressedId     = null;
            _dragging      = false;
        }
    }

    private void OnPinPointerReleased(object? sender, PointerReleasedEventArgs e)
    {
        if (!_dragging)
        {
            _pressedButton = null;
            _pressedId     = null;
        }
    }

    private void OnPinDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = e.Data.Contains(DragFormat)
            ? DragDropEffects.Move
            : DragDropEffects.None;
        e.Handled = true;
    }

    private void OnPinDrop(object? sender, DragEventArgs e)
    {
        if (e.Data.Get(DragFormat) is not string sourceId) return;
        var btn = PinButtonFromSource(e.Source);
        if (btn?.DataContext is not PinnedEntry target) return;

        if (DataContext is Text2ClipboardViewModel vm)
            vm.ReorderPin(sourceId, target.Identifier);
        e.Handled = true;
    }
}
