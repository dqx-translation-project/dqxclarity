using Avalonia;
using Avalonia.Media;
using Avalonia.Styling;

namespace DqxClarity.Services;

public static class ThemeService
{
    private static readonly Dictionary<string, Dictionary<string, string>> Themes = new()
    {
        ["rosie"]    = new() { ["AppBg"]="#060d0b",["AppSurface"]="#0c1814",["AppSurface2"]="#142018",["AppBorder"]="#203828",["AppText"]="#c8e8de",["AppMuted"]="#508870",["AppAccent"]="#18b090",["AppSuccess"]="#4caf82",["AppDanger"]="#e05c6a" },
        ["asbal"]    = new() { ["AppBg"]="#0d0608",["AppSurface"]="#150b10",["AppSurface2"]="#1e1018",["AppBorder"]="#3a1a28",["AppText"]="#f0e0e8",["AppMuted"]="#9a6878",["AppAccent"]="#c82040",["AppSuccess"]="#4caf82",["AppDanger"]="#e07040" },
        ["duston"]   = new() { ["AppBg"]="#141008",["AppSurface"]="#1c170a",["AppSurface2"]="#261e10",["AppBorder"]="#3c3018",["AppText"]="#e8dcc8",["AppMuted"]="#8a7858",["AppAccent"]="#a87830",["AppSuccess"]="#4a8a3a",["AppDanger"]="#c04030" },
        ["fostail"]  = new() { ["AppBg"]="#0d0b14",["AppSurface"]="#131020",["AppSurface2"]="#1a1530",["AppBorder"]="#2c2545",["AppText"]="#d8d0f0",["AppMuted"]="#7870a8",["AppAccent"]="#9068e0",["AppSuccess"]="#4caf82",["AppDanger"]="#e05c6a" },
        ["lushenda"] = new() { ["AppBg"]="#0a0810",["AppSurface"]="#130f1e",["AppSurface2"]="#1c1630",["AppBorder"]="#362248",["AppText"]="#ecd8f8",["AppMuted"]="#7848a8",["AppAccent"]="#2aac58",["AppSuccess"]="#4caf82",["AppDanger"]="#e05c6a" },
        ["anlucia"]  = new() { ["AppBg"]="#fdf6ec",["AppSurface"]="#fffaf3",["AppSurface2"]="#f2e6d2",["AppBorder"]="#dccaac",["AppText"]="#2c1a08",["AppMuted"]="#8a6e52",["AppAccent"]="#b87228",["AppSuccess"]="#4a7a2a",["AppDanger"]="#c03020" },
        ["estella"]  = new() { ["AppBg"]="#eef4f8",["AppSurface"]="#f5f9fc",["AppSurface2"]="#dde8f0",["AppBorder"]="#b8ccd8",["AppText"]="#0e1e28",["AppMuted"]="#4a6a80",["AppAccent"]="#3878aa",["AppSuccess"]="#2a7a3a",["AppDanger"]="#c04040" },
        ["kyururu"]  = new() { ["AppBg"]="#edfaf5",["AppSurface"]="#f5fdfa",["AppSurface2"]="#d8f4ec",["AppBorder"]="#a8e0cc",["AppText"]="#0a2820",["AppMuted"]="#3a7860",["AppAccent"]="#22aa78",["AppSuccess"]="#2a8a4a",["AppDanger"]="#c03040" },
        ["maille"]   = new() { ["AppBg"]="#fdf0f2",["AppSurface"]="#fff5f7",["AppSurface2"]="#f0dfe2",["AppBorder"]="#dcc8cc",["AppText"]="#2a1018",["AppMuted"]="#8a5868",["AppAccent"]="#b05870",["AppSuccess"]="#2a7a3a",["AppDanger"]="#c03030" },
        ["mereade"]  = new() { ["AppBg"]="#fff5ed",["AppSurface"]="#fff9f5",["AppSurface2"]="#ffe8d8",["AppBorder"]="#f0c8a8",["AppText"]="#2a1008",["AppMuted"]="#8a5830",["AppAccent"]="#d06820",["AppSuccess"]="#2a7a3a",["AppDanger"]="#c03030" },
        ["seraphi"]  = new() { ["AppBg"]="#fdf8e0",["AppSurface"]="#fffcf0",["AppSurface2"]="#f8edbc",["AppBorder"]="#e0cc70",["AppText"]="#1a1600",["AppMuted"]="#b07028",["AppAccent"]="#3a6abf",["AppSuccess"]="#2a7a3a",["AppDanger"]="#c04040" },
        ["yuliza"]   = new() { ["AppBg"]="#edf2fa",["AppSurface"]="#f5f8ff",["AppSurface2"]="#dce5f5",["AppBorder"]="#b8c8e8",["AppText"]="#081030",["AppMuted"]="#3a5080",["AppAccent"]="#2854c8",["AppSuccess"]="#2a7a3a",["AppDanger"]="#c04040" },
    };

    public static readonly (string Id, string Label)[] DarkThemes =
    [
        ("rosie", "Rosie"), ("asbal", "Asbal"), ("duston", "Duston"),
        ("fostail", "Fostail"), ("lushenda", "Lushenda"),
    ];

    public static readonly (string Id, string Label)[] LightThemes =
    [
        ("anlucia","Anlucia"),("estella","Estella"),("kyururu","Kyururu"),
        ("maille","Maille"),("mereade","Mereade"),("seraphi","Seraphi"),("yuliza","Yuliza"),
    ];

    public static string GetCharacterImageUri(string name)
    {
        if (LightThemes.Any(t => t.Id == name))
            return $"avares://dqxclarity/Assets/{name}.png";
        if (DarkThemes.Any(t => t.Id == name && t.Id != "rosie"))
            return $"avares://dqxclarity/Assets/{name}.png";
        return "avares://dqxclarity/Assets/Rosie.png";
    }

    public static void Apply(string name)
    {
        if (!Themes.TryGetValue(name, out var colors))
            colors = Themes["rosie"];

        var res = Application.Current!.Resources;
        foreach (var (key, hex) in colors)
        {
            var color = Color.Parse(hex);
            res[key] = new SolidColorBrush(color);
            res[key + "Color"] = color;
        }

        var isLight = LightThemes.Any(t => t.Id == name);
        Application.Current.RequestedThemeVariant =
            isLight ? ThemeVariant.Light : ThemeVariant.Dark;
    }

    public static Color GetColor(string themeName, string key)
    {
        if (!Themes.TryGetValue(themeName, out var colors)) colors = Themes["rosie"];
        return colors.TryGetValue(key, out var hex) ? Color.Parse(hex) : Colors.Transparent;
    }
}
