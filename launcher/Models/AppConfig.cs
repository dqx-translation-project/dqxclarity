namespace DqxClarity.Launcher.Models;

public class LauncherConfig
{
    public bool Nameplates { get; set; }
    public bool DebugLogging { get; set; }
    public bool CommunityLogging { get; set; }
    public bool SimultaneousLaunch { get; set; }
    public string Theme { get; set; } = "rosie";
    public bool SeenWelcomeMessage { get; set; }
}

public class TranslationConfig
{
    public string TranslateService   { get; set; } = "googlefree";
    public string TranslateKey       { get; set; } = "";
    public string ChatGptModel       { get; set; } = "gpt-4o-mini";
    public string OllamaUrl          { get; set; } = "http://localhost:11434";
    public string OllamaModel        { get; set; } = "llama3";
    public string LibreTranslateUrl  { get; set; } = "https://libretranslate.com";
    public bool   EnableCommunityApi { get; set; }
    public string CommunityApiKey    { get; set; } = "";
}

public class GameConfig
{
    public string InstallDirectory { get; set; } = "";
    public string LocaleEmulatorDirectory { get; set; } = "";
}

public class AppConfig
{
    public LauncherConfig Launcher { get; set; } = new();
    public TranslationConfig Translation { get; set; } = new();
    public GameConfig Game { get; set; } = new();
}
