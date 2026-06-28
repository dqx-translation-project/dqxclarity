using CommunityToolkit.Mvvm.ComponentModel;

namespace DqxClarity.Launcher.Models;

public class LauncherConfig
{
    public bool Nameplates { get; set; }
    public bool DebugLogging { get; set; }
    public bool CommunityLogging { get; set; }
    public bool SimultaneousLaunch { get; set; }
    public bool DirectLogin { get; set; }
    public int DirectLoginAccountNumber { get; set; }
    public string Theme { get; set; } = "rosie";
    public bool SeenWelcomeMessage { get; set; }
    public bool BannerCollapsed { get; set; }
    public bool LanguagePackSupport { get; set; }
    public bool LanguagePackFirstRunDone { get; set; }
    public bool AutomaticLanguagePackUpdates { get; set; }
    public List<string> ActiveLanguagePacks { get; set; } = [];
}

public partial class LanguagePack : ObservableObject
{
    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _author = "";
    [ObservableProperty] private string _language = "";
    [ObservableProperty] private string _created = "";   // display form of the CLPK builtAt timestamp
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private string _path = "";
    [ObservableProperty] private string _downloadUrl = "";
    [ObservableProperty] private bool _hasUpdate;
    [ObservableProperty] private bool _isActive;
    [ObservableProperty] private bool _canActivate;
    [ObservableProperty] private List<string> _gameMods = [];
}

public class TranslationConfig
{
    public string TranslateService   { get; set; } = "googlefree";
    public string TranslateKey       { get; set; } = "";
    public string ChatGptModel       { get; set; } = "gpt-4o-mini";
    public string OllamaUrl          { get; set; } = "http://localhost:11434";
    public string OllamaModel        { get; set; } = "llama3";
    public string LibreTranslateUrl  { get; set; } = "https://libretranslate.com";
}

public class GameConfig
{
    public string InstallDirectory { get; set; } = "";
    public string SaveFolderPath { get; set; } = "";
}

public class SavedPlayer
{
    public int Number { get; set; }
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public bool IsTrialAccount { get; set; }
    public string DisplayName => IsTrialAccount ? "Easy Play Account" : Username;
}

public class AppConfig
{
    public LauncherConfig Launcher { get; set; } = new();
    public TranslationConfig Translation { get; set; } = new();
    public GameConfig Game { get; set; } = new();
    public List<SavedPlayer> Players { get; set; } = new();
}
