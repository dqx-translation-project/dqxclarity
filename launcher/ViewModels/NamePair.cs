using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace DqxClarity.Launcher.ViewModels;

public partial class NamePair : ObservableObject
{
    [ObservableProperty] private string _japanese = "";
    [ObservableProperty] private string _english  = "";

    public IRelayCommand RemoveCommand { get; }

    public NamePair(string japanese, string english, Action<NamePair> remove)
    {
        _japanese = japanese;
        _english  = english;
        RemoveCommand = new RelayCommand(() => remove(this));
    }
}
