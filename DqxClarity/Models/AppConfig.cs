using CommunityToolkit.Mvvm.ComponentModel;

namespace DqxClarity.Models;

public class LauncherConfig
{
    public bool NameplatesPlayer { get; set; } = true;
    public bool NameplatesNpc { get; set; } = true;
    public bool NameplatesMonster { get; set; } = true;
    public bool DebugLogging { get; set; }
    public bool CommunityLogging { get; set; }
    public bool SimultaneousLaunch { get; set; }
    public bool DirectLogin { get; set; }
    public int DirectLoginAccountNumber { get; set; }
    public string Theme { get; set; } = "rosie";
    public bool SeenWelcomeMessage { get; set; }
    public bool BannerCollapsed { get; set; }

    // ── Language packs (CLPK / DragonHook) ─────────────────────────────
    public bool LanguagePackFirstRunDone { get; set; }
    public bool AutomaticLanguagePackUpdates { get; set; } = true;
    public List<string> ActiveLanguagePacks { get; set; } = [];

    // Hidden from the GUI, must be entered in the .ini file manually.
    public bool DisableTranslations { get; set; }
}

/// <summary>A scanned language pack (.clpk) entry shown in the Language tab's list. Observable so
/// the list UI (active checkbox, update status, etc.) updates live as scans/downloads/updates run.</summary>
public partial class LanguagePack : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LanguageDisplay))]
    private string _language = "";

    /// <summary>Human-readable language name (e.g. "English"); this is the pack's display identity.</summary>
    public string LanguageDisplay => LanguageNames.DisplayName(Language);

    [ObservableProperty] private string _author = "";
    [ObservableProperty] private string _updated = "";   // display form of the CLPK builtAt timestamp
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private string _path = "";
    [ObservableProperty] private string _downloadUrl = "";
    [ObservableProperty] private bool _hasUpdate;
    [ObservableProperty] private bool _isActive;
    [ObservableProperty] private bool _canActivate;
}

public class TranslationConfig
{
    public string TranslateService   { get; set; } = "none";
    public string TranslateKey       { get; set; } = "";
    public string ChatGptModel       { get; set; } = "gpt-4o-mini";
    public string OllamaUrl          { get; set; } = "http://localhost:11434";
    public string OllamaModel        { get; set; } = "llama3";
    public string LibreTranslateUrl  { get; set; } = "https://libretranslate.com";
    public bool   EnableCommunityApi { get; set; }
    public string CommunityApiKey    { get; set; } = "";

    public string TargetLanguage     { get; set; } = "en";
    public string TargetLanguageName { get; set; } = "English";
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
