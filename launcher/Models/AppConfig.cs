namespace DqxClarity.Launcher.Models;

public class LauncherConfig
{
    public bool Nameplates { get; set; }
    public bool DebugLogging { get; set; }
    public bool CommunityLogging { get; set; }
    public bool SimultaneousLaunch { get; set; }
    public bool LaunchSendToChat { get; set; }
    public string Theme { get; set; } = "rosie";
}

public class TranslationConfig
{
    public bool EnableDeepLTranslate { get; set; }
    public string DeepLTranslateKey { get; set; } = "";
    public bool EnableGoogleTranslate { get; set; }
    public string GoogleTranslateKey { get; set; } = "";
    public bool EnableGoogleTranslateFree { get; set; }
    public bool EnableCommunityApi { get; set; }
    public string CommunityApiKey { get; set; } = "";
}

public class GameConfig
{
    public string InstallDirectory { get; set; } = "";
}

public class AppConfig
{
    public LauncherConfig Launcher { get; set; } = new();
    public TranslationConfig Translation { get; set; } = new();
    public GameConfig Game { get; set; } = new();
}
