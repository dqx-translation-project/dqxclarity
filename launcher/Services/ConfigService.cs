using DqxClarity.Launcher.Models;

namespace DqxClarity.Launcher.Services;

public class ConfigService
{
    public const string DefaultDqxDir = @"C:\Program Files (x86)\SquareEnix\DRAGON QUEST X";

    private static string ExeDir()
    {
        var exe = Environment.ProcessPath ?? throw new Exception("Cannot determine executable path");
        return Path.GetDirectoryName(exe) ?? throw new Exception("Cannot determine executable directory");
    }

    private string AppDir()
    {
        var dir = ExeDir();
        for (int i = 0; i < 4; i++)
        {
            if (File.Exists(Path.Combine(dir, "main.py")))
                return Path.GetFullPath(dir);
            dir = Path.Combine(dir, "..");
        }
        return Path.GetFullPath(Path.Combine(ExeDir(), ".."));
    }

    private string ConfigPath() => Path.Combine(AppDir(), "user_settings.ini");

    private static Dictionary<string, Dictionary<string, string>> ParseIni(string content)
    {
        var result = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        var current = "";
        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                current = line[1..^1].ToLowerInvariant();
            }
            else if (line.Contains('='))
            {
                var idx = line.IndexOf('=');
                var key = line[..idx].Trim().ToLowerInvariant();
                var val = line[(idx + 1)..].Trim();
                if (!result.ContainsKey(current)) result[current] = new(StringComparer.OrdinalIgnoreCase);
                result[current][key] = val;
            }
        }
        return result;
    }

    private static bool ToBool(string? val) =>
        val is "True" or "true" or "1";

    private static string BoolToIni(bool b) => b ? "True" : "False";

    private static void WriteKv(System.Text.StringBuilder sb, string key, string value)
    {
        if (string.IsNullOrEmpty(value))
            sb.AppendLine($"{key} =");
        else
            sb.AppendLine($"{key} = {value}");
    }

    private void UpdateIniValue(string path, string section, string key, string value)
    {
        // Parse the existing file into an ordered list of sections, each with an ordered list of key/value pairs.
        var sectionOrder = new List<string>();
        var sectionData  = new Dictionary<string, List<(string K, string V)>>(StringComparer.OrdinalIgnoreCase);

        if (File.Exists(path))
        {
            string? current = null;
            foreach (var rawLine in File.ReadAllText(path).Split('\n'))
            {
                var trimmed = rawLine.Trim();
                if (trimmed.StartsWith('[') && trimmed.EndsWith(']'))
                {
                    current = trimmed[1..^1];
                    if (!sectionData.ContainsKey(current))
                    {
                        sectionOrder.Add(current);
                        sectionData[current] = new();
                    }
                }
                else if (current != null && trimmed.Contains('='))
                {
                    var eqIdx = trimmed.IndexOf('=');
                    sectionData[current].Add((trimmed[..eqIdx].Trim(), trimmed[(eqIdx + 1)..].Trim()));
                }
            }
        }

        // Ensure the target section exists.
        if (!sectionData.ContainsKey(section))
        {
            sectionOrder.Add(section);
            sectionData[section] = new();
        }

        // Update the key in the target section, or append it if missing.
        var entries = sectionData[section];
        var idx     = entries.FindIndex(e => e.K.Equals(key, StringComparison.OrdinalIgnoreCase));
        if (idx >= 0)
            entries[idx] = (key, value);
        else
            entries.Add((key, value));

        // Rewrite the entire file with consistent formatting:
        // blank line before every section except the first, no blank lines between keys.
        var sb = new System.Text.StringBuilder();
        for (var i = 0; i < sectionOrder.Count; i++)
        {
            if (i > 0) sb.AppendLine();
            var name = sectionOrder[i];
            sb.AppendLine($"[{name}]");
            foreach (var (k, v) in sectionData[name])
                WriteKv(sb, k, v);
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, sb.ToString().TrimEnd('\r', '\n') + Environment.NewLine);
    }

    private static TranslationConfig LoadTranslationConfig(Dictionary<string, string> t)
    {
        // Migrate old per-service boolean flags to the new translate_service string.
        var service = t.GetValueOrDefault("translate_service");
        var key     = t.GetValueOrDefault("translate_key") ?? "";
        if (string.IsNullOrEmpty(service))
        {
            if (ToBool(t.GetValueOrDefault("enabledeepltranslate")))
            {
                service = "deepl";
                key     = t.GetValueOrDefault("deepltranslatekey") ?? "";
            }
            else if (ToBool(t.GetValueOrDefault("enablegoogletranslate")))
            {
                service = "google";
                key     = t.GetValueOrDefault("googletranslatekey") ?? "";
            }
            else if (ToBool(t.GetValueOrDefault("enablegoogletranslatefree")))
            {
                service = "googlefree";
            }
            else
            {
                service = "googlefree";
            }
        }

        return new TranslationConfig
        {
            TranslateService  = service,
            TranslateKey      = key,
            ChatGptModel      = t.GetValueOrDefault("chatgpt_model")      ?? "gpt-4o-mini",
            OllamaUrl         = t.GetValueOrDefault("ollama_url")         ?? "http://localhost:11434",
            OllamaModel       = t.GetValueOrDefault("ollama_model")       ?? "llama3",
            LibreTranslateUrl = t.GetValueOrDefault("libretranslate_url") ?? "https://libretranslate.com",
        };
    }

    public AppConfig Load()
    {
        var path = ConfigPath();
        if (!File.Exists(path))
            return new AppConfig();

        var content = File.ReadAllText(path);
        var sections = ParseIni(content);

        var l = sections.GetValueOrDefault("launcher") ?? [];
        var t = sections.GetValueOrDefault("translation") ?? [];
        var c = sections.GetValueOrDefault("config") ?? [];

        var p = sections.GetValueOrDefault("players") ?? [];

        return new AppConfig
        {
            Launcher = new LauncherConfig
            {
                Nameplates               = ToBool(l.GetValueOrDefault("nameplates")),
                DebugLogging             = ToBool(l.GetValueOrDefault("debuglogging")),
                CommunityLogging         = ToBool(l.GetValueOrDefault("communitylogging")),
                SimultaneousLaunch       = ToBool(l.GetValueOrDefault("simultaneouslaunch")),
                DirectLogin              = ToBool(l.GetValueOrDefault("directlogin")),
                DirectLoginAccountNumber = int.TryParse(l.GetValueOrDefault("directloginaccountnumber"), out var dla) ? dla : 0,
                Theme                    = l.GetValueOrDefault("theme") ?? "rosie",
                SeenWelcomeMessage       = ToBool(l.GetValueOrDefault("seenwelcomemessage")),
                BannerCollapsed          = ToBool(l.GetValueOrDefault("bannercollapsed")),
            },
            Translation = LoadTranslationConfig(t),
            Game = new GameConfig
            {
                InstallDirectory        = c.GetValueOrDefault("installdirectory") ?? "",
                SaveFolderPath          = c.GetValueOrDefault("savefolderdirectory") ?? "",
            },
            Players = LoadPlayers(p),
        };
    }

    public void Save(LauncherConfig launcher, TranslationConfig translation)
    {
        var path = ConfigPath();
        var existing = File.Exists(path) ? ParseIni(File.ReadAllText(path)) : [];
        var configSection  = existing.GetValueOrDefault("config")  ?? [];
        var playersSection = existing.GetValueOrDefault("players") ?? [];
        var configPairs    = configSection.OrderBy(kv => kv.Key).ToList();
        var existingLauncher = existing.GetValueOrDefault("launcher") ?? [];
        var seenWelcome      = existingLauncher.GetValueOrDefault("seenwelcomemessage") ?? BoolToIni(launcher.SeenWelcomeMessage);
        var bannerCollapsed  = existingLauncher.GetValueOrDefault("bannercollapsed")    ?? BoolToIni(launcher.BannerCollapsed);

        var sb = new System.Text.StringBuilder();

        // translation section — always first, no leading blank line
        sb.AppendLine("[translation]");
        WriteKv(sb, "translate_service",   translation.TranslateService);
        WriteKv(sb, "translate_key",       translation.TranslateKey);
        WriteKv(sb, "chatgpt_model",       translation.ChatGptModel);
        WriteKv(sb, "ollama_url",          translation.OllamaUrl);
        WriteKv(sb, "ollama_model",        translation.OllamaModel);
        WriteKv(sb, "libretranslate_url",  translation.LibreTranslateUrl);

        if (configPairs.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("[config]");
            foreach (var (k, v) in configPairs)
                WriteKv(sb, k, v);
        }

        if (playersSection.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("[players]");
            foreach (var (k, v) in playersSection.OrderBy(kv => kv.Key))
                WriteKv(sb, k, v);
        }

        sb.AppendLine();
        sb.AppendLine("[launcher]");
        WriteKv(sb, "communitylogging",         BoolToIni(launcher.CommunityLogging));
        WriteKv(sb, "nameplates",               BoolToIni(launcher.Nameplates));
        WriteKv(sb, "debuglogging",             BoolToIni(launcher.DebugLogging));
        WriteKv(sb, "simultaneouslaunch",       BoolToIni(launcher.SimultaneousLaunch));
        WriteKv(sb, "directlogin",              BoolToIni(launcher.DirectLogin));
        WriteKv(sb, "directloginaccountnumber", launcher.DirectLoginAccountNumber.ToString());
        WriteKv(sb, "theme",                    launcher.Theme);
        WriteKv(sb, "seenwelcomemessage",       seenWelcome);
        WriteKv(sb, "bannercollapsed",          bannerCollapsed);

        var dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(path, sb.ToString().TrimEnd('\r', '\n') + Environment.NewLine);
    }

    public void SaveTheme(string theme)
    {
        var path = ConfigPath();
        UpdateIniValue(path, "launcher", "theme", theme);
    }

    public void SaveGameDir(string dir)
    {
        var path = ConfigPath();
        UpdateIniValue(path, "config", "installdirectory", dir.Replace('\\', '/'));
    }

    public void SaveDirectLogin(bool value) =>
        UpdateIniValue(ConfigPath(), "launcher", "directlogin", BoolToIni(value));

    public void SaveDirectLoginAccountNumber(int number) =>
        UpdateIniValue(ConfigPath(), "launcher", "directloginaccountnumber", number.ToString());

    public bool ValidateSaveFolder(string dir, out string error)
    {
        if (!Directory.Exists(dir))
        {
            error = "The selected folder does not exist.";
            return false;
        }
        error = "";
        return true;
    }

    private static List<Models.SavedPlayer> LoadPlayers(Dictionary<string, string> p)
    {
        var players = new List<Models.SavedPlayer>();
        for (var n = 1; n <= 4; n++)
        {
            var username = p.GetValueOrDefault($"player{n}_username") ?? "";
            var password = p.GetValueOrDefault($"player{n}_password") ?? "";
            if (!string.IsNullOrEmpty(username))
                players.Add(new Models.SavedPlayer { Number = n - 1, Username = username, Password = password });
        }
        return players;
    }

    public void SavePlayer(Models.SavedPlayer player)
    {
        var path = ConfigPath();
        UpdateIniValue(path, "players", $"player{player.Number + 1}_username", player.Username);
        UpdateIniValue(path, "players", $"player{player.Number + 1}_password", player.Password);
    }

    public void RemovePlayer(int number)
    {
        var path = ConfigPath();
        UpdateIniValue(path, "players", $"player{number + 1}_username", "");
        UpdateIniValue(path, "players", $"player{number + 1}_password", "");
    }

    /// <summary>Returns the next unused player slot (0–3), or null if all are taken.</summary>
    public int? NextPlayerNumber(List<Models.SavedPlayer> existing)
    {
        var taken = existing.Select(p => p.Number).ToHashSet();
        for (var n = 0; n <= 3; n++)
            if (!taken.Contains(n)) return n;
        return null;
    }

    public void SaveSeenWelcomeMessage()
    {
        var path = ConfigPath();
        UpdateIniValue(path, "launcher", "seenwelcomemessage", "True");
    }

    public void SaveBannerCollapsed(bool value) =>
        UpdateIniValue(ConfigPath(), "launcher", "bannercollapsed", BoolToIni(value));

    public string GetVersion()
    {
        try
        {
            var versionFile = Path.Combine(AppDir(), "version.update");
            if (!File.Exists(versionFile)) return "???";
            var v = File.ReadAllText(versionFile).Trim();
            return string.IsNullOrEmpty(v) ? "???" : v;
        }
        catch { return "???"; }
    }

    public bool ValidateDqxDir(string dir, out string error)
    {
        var idx = Path.Combine(dir, "Game", "Content", "Data", "data00000000.win32.idx");
        if (File.Exists(idx)) { error = ""; return true; }
        error = "Could not find Game/Content/Data/data00000000.win32.idx in the selected folder. Make sure you selected the top-level DQX installation folder.";
        return false;
    }

    public void LaunchDqx(string installDir)
    {
        var dqxExe = Path.Combine(installDir, "Boot", "DQXBoot.exe");
        if (!File.Exists(dqxExe)) throw new FileNotFoundException($"DQXBoot.exe not found at {dqxExe}");

        var psi = new System.Diagnostics.ProcessStartInfo(dqxExe)
        {
            WorkingDirectory = Path.Combine(installDir, "Boot"),
            UseShellExecute  = false,
            CreateNoWindow   = true,
        };
        System.Diagnostics.Process.Start(psi);
    }

    public void LaunchDqxConfig(string installDir)
    {
        var exe = Path.Combine(installDir, "Game", "DQXConfig.exe");
        if (!File.Exists(exe)) throw new FileNotFoundException($"DQXConfig.exe not found at {exe}");
        var psi = new System.Diagnostics.ProcessStartInfo(exe)
        {
            WorkingDirectory = Path.Combine(installDir, "Game"),
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        System.Diagnostics.Process.Start(psi);
    }

    public string ReadNameOverrides()
    {
        try
        {
            var path = Path.Combine(AppDir(), "misc_files", "name_overrides.json");
            return File.Exists(path) ? File.ReadAllText(path) : "misc_files/name_overrides.json not found";
        }
        catch { return "misc_files/name_overrides.json not found"; }
    }

    public void SaveNameOverrides(string content)
    {
        var path = Path.Combine(AppDir(), "misc_files", "name_overrides.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    public string ReadUserPhrases()
    {
        try
        {
            var path = Path.Combine(AppDir(), "misc_files", "user_phrases.json");
            return File.Exists(path) ? File.ReadAllText(path) : "";
        }
        catch { return ""; }
    }

    public void SaveUserPhrases(string content)
    {
        var path = Path.Combine(AppDir(), "misc_files", "user_phrases.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    public bool HasAutorunFlag() => Environment.GetCommandLineArgs().Any(a => a == "/r");
}
