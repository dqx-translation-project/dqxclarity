using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace DqxClarity.ViewModels;

public partial class NamePair : ObservableObject
{
    [ObservableProperty] private string _japanese = "";
    [ObservableProperty] private string _preferred = "";

    public IRelayCommand RemoveCommand { get; }

    public NamePair(string japanese, string preferred, Action<NamePair> remove)
    {
        _japanese  = japanese;
        _preferred = preferred;
        RemoveCommand = new RelayCommand(() => remove(this));
    }
}
