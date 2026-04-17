using DqxClarity.Launcher.Models;

namespace DqxClarity.Launcher.Services;

public class ConfigService
{
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
        var content = File.Exists(path) ? File.ReadAllText(path) : "";
        var sb = new System.Text.StringBuilder();
        var inTarget = false;
        var keyWritten = false;
        var sectionFound = false;

        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var trimmed = line.Trim();
            if (trimmed.StartsWith('[') && trimmed.EndsWith(']'))
            {
                if (inTarget && !keyWritten)
                {
                    WriteKv(sb, key, value);
                    keyWritten = true;
                }
                var sec = trimmed[1..^1].ToLowerInvariant();
                inTarget = sec == section.ToLowerInvariant();
                if (inTarget) sectionFound = true;
                sb.AppendLine(line);
            }
            else if (inTarget)
            {
                var eqIdx = trimmed.IndexOf('=');
                if (eqIdx >= 0)
                {
                    var k = trimmed[..eqIdx].Trim().ToLowerInvariant();
                    if (k == key.ToLowerInvariant())
                    {
                        WriteKv(sb, key, value);
                        keyWritten = true;
                        continue;
                    }
                }
                sb.AppendLine(line);
            }
            else
            {
                sb.AppendLine(line);
            }
        }

        if (inTarget && !keyWritten)
            WriteKv(sb, key, value);

        if (!sectionFound)
        {
            if (sb.Length > 0 && !sb.ToString().EndsWith("\n\n"))
                sb.AppendLine();
            sb.AppendLine($"[{section}]");
            WriteKv(sb, key, value);
        }

        File.WriteAllText(path, sb.ToString());
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

        return new AppConfig
        {
            Launcher = new LauncherConfig
            {
                Nameplates       = ToBool(l.GetValueOrDefault("nameplates")),
                DebugLogging     = ToBool(l.GetValueOrDefault("debuglogging")),
                CommunityLogging = ToBool(l.GetValueOrDefault("communitylogging")),
                SimultaneousLaunch = ToBool(l.GetValueOrDefault("simultaneouslaunch")),
                Theme            = l.GetValueOrDefault("theme") ?? "rosie",
            },
            Translation = new TranslationConfig
            {
                EnableDeepLTranslate      = ToBool(t.GetValueOrDefault("enabledeepltranslate")),
                DeepLTranslateKey         = t.GetValueOrDefault("deepltranslatekey") ?? "",
                EnableGoogleTranslate     = ToBool(t.GetValueOrDefault("enablegoogletranslate")),
                GoogleTranslateKey        = t.GetValueOrDefault("googletranslatekey") ?? "",
                EnableGoogleTranslateFree = ToBool(t.GetValueOrDefault("enablegoogletranslatefree")),
                EnableCommunityApi        = ToBool(t.GetValueOrDefault("enablecommunityapi")),
                CommunityApiKey           = t.GetValueOrDefault("communityapikey") ?? "",
            },
            Game = new GameConfig
            {
                InstallDirectory = c.GetValueOrDefault("installdirectory") ?? "",
            },
        };
    }

    public void Save(LauncherConfig launcher, TranslationConfig translation)
    {
        var path = ConfigPath();
        var existing = File.Exists(path) ? ParseIni(File.ReadAllText(path)) : [];
        var configSection = existing.GetValueOrDefault("config") ?? [];
        var configPairs = configSection.OrderBy(kv => kv.Key).ToList();

        var sb = new System.Text.StringBuilder();

        sb.AppendLine("[translation]");
        WriteKv(sb, "enabledeepltranslate",      BoolToIni(translation.EnableDeepLTranslate));
        WriteKv(sb, "deepltranslatekey",          translation.DeepLTranslateKey);
        WriteKv(sb, "enablegoogletranslate",      BoolToIni(translation.EnableGoogleTranslate));
        WriteKv(sb, "googletranslatekey",         translation.GoogleTranslateKey);
        WriteKv(sb, "enablegoogletranslatefree",  BoolToIni(translation.EnableGoogleTranslateFree));
        WriteKv(sb, "enablecommunityapi",         BoolToIni(translation.EnableCommunityApi));
        WriteKv(sb, "communityapikey",            translation.CommunityApiKey);
        sb.AppendLine();

        if (configPairs.Count > 0)
        {
            sb.AppendLine("[config]");
            foreach (var (k, v) in configPairs)
                WriteKv(sb, k, v);
            sb.AppendLine();
        }

        sb.AppendLine("[launcher]");
        WriteKv(sb, "communitylogging",   BoolToIni(launcher.CommunityLogging));
        WriteKv(sb, "nameplates",         BoolToIni(launcher.Nameplates));
        WriteKv(sb, "debuglogging",       BoolToIni(launcher.DebugLogging));
        WriteKv(sb, "simultaneouslaunch", BoolToIni(launcher.SimultaneousLaunch));
        WriteKv(sb, "theme",              launcher.Theme);

        var dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(path, sb.ToString());
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
        var exe = Path.Combine(installDir, "Boot", "DQXBoot.exe");
        if (!File.Exists(exe)) throw new FileNotFoundException($"DQXBoot.exe not found at {exe}");
        var psi = new System.Diagnostics.ProcessStartInfo(exe)
        {
            WorkingDirectory = Path.Combine(installDir, "Boot"),
            UseShellExecute = false,
            CreateNoWindow = true,
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

    public bool HasAutorunFlag() => Environment.GetCommandLineArgs().Any(a => a == "/r");

    public string AppDirectory() => AppDir();
    public string ExeDirectory() => ExeDir();
}
