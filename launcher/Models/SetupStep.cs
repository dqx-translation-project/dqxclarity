using CommunityToolkit.Mvvm.ComponentModel;

namespace DqxClarity.Launcher.Models;

public enum StepStatus { Pending, Running, Done, Error }

public partial class SetupStep : ObservableObject
{
    public string Id    { get; init; } = "";
    public string Label { get; init; } = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsRunning), nameof(IsDone), nameof(IsError), nameof(IsPending),
                               nameof(IsVisible))]
    private StepStatus _status = StepStatus.Pending;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasMessage))]
    private string _message = "";

    public bool IsRunning => Status == StepStatus.Running;
    public bool IsDone    => Status == StepStatus.Done;
    public bool IsError   => Status == StepStatus.Error;
    public bool IsPending => Status == StepStatus.Pending;

    // A step is visible once it's no longer pending
    public bool IsVisible => Status != StepStatus.Pending;

    public bool HasMessage => !string.IsNullOrEmpty(Message) && Status != StepStatus.Done;
}

public record SetupEvent(string Step, string Status, string Message);
