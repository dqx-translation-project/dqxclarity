namespace DqxClarity.Models;

public class LauncherConfig
{
    // Split out from a single "Nameplates" checkbox so each entity category
    // can be turned off independently. Gates ONLY whether EntityPacket
    // rewrites that category's nameplate text -- it never affects packet
    // parsing itself (see EntityPacket's doc comment), so turning off e.g.
    // Player nameplates can't break PlayerContext's <pnplacehold> character
    // identification, which reads the untranslated packet regardless.
    // Default true for all three so an existing user upgrading (whose ini
    // has none of these keys yet) keeps getting nameplates translated. The
    // old single "Nameplates" checkbox never actually gated anything -- the
    // --nameplates arg it produced was read into an explicitly-discarded
    // parameter in MainViewModel.OnRunRequested -- so nameplate translation
    // was unconditionally on before this split either way; defaulting to
    // true just keeps that same effective behavior for anyone who hasn't
    // touched these settings yet.
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
