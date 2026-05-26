using System.Text;
using System.Xml.Linq;
using System.Xml.XPath;

namespace DqxClarity.Services;

public class DqxPlayer
{
    public required string Token { get; init; }
    public required int Number { get; init; }
}

public class DqxTrialInfo
{
    public required string Id    { get; init; }
    public required string Token { get; init; }
    public required string Code  { get; init; }
}


/// <summary>
/// Reads and writes the obfuscated dqxPlayerList.xml from the DQX save folder.
/// The file uses filename obfuscation (seed 0x11) and XOR content obfuscation
/// with a key derived from a custom CRC32 of the current Windows username.
/// </summary>
public static class PlayerListReader
{
    public static readonly string DefaultSaveFolder =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                     "My Games", "DRAGON QUEST X");

    public static string Resolve(string? configured) =>
        !string.IsNullOrWhiteSpace(configured) ? configured : DefaultSaveFolder;

    public static Task<List<DqxPlayer>> ReadAsync(string? saveFolderPath = null) =>
        Task.Run(() => Read(Resolve(saveFolderPath)));

    public static Task WritePlayerAsync(DqxPlayer player, string? saveFolderPath = null) =>
        Task.Run(() => WritePlayer(player, Resolve(saveFolderPath)));

    public static Task RemovePlayerAsync(int number, string? saveFolderPath = null) =>
        Task.Run(() => RemovePlayer(number, Resolve(saveFolderPath)));

    public static Task<DqxTrialInfo?> ReadTrialInfoAsync(string? saveFolderPath = null) =>
        Task.Run(() => ReadTrialInfo(Resolve(saveFolderPath)));

    public static Task UpdateTrialTokenAsync(string newToken, string? saveFolderPath = null) =>
        Task.Run(() => UpdateTrialToken(newToken, Resolve(saveFolderPath)));

    private static List<DqxPlayer> Read(string folder)
    {
        var path = GetObfuscatedPath(folder);
        if (!File.Exists(path)) return [];

        var xml = Decrypt(File.ReadAllBytes(path));
        var doc = XDocument.Parse(xml);
        return doc.XPathSelectElements("//Player")
            .Select(el =>
            {
                var token = el.Attribute("Token")?.Value;
                if (!int.TryParse(el.Attribute("Number")?.Value, out var number)) return null;
                if (string.IsNullOrEmpty(token)) return null;
                return new DqxPlayer { Token = token, Number = number };
            })
            .OfType<DqxPlayer>()
            .ToList();
    }

    private static void WritePlayer(DqxPlayer player, string folder)
    {
        Directory.CreateDirectory(folder);
        var path = GetObfuscatedPath(folder);

        XDocument doc;
        if (File.Exists(path))
        {
            doc = XDocument.Parse(Decrypt(File.ReadAllBytes(path)));
        }
        else
        {
            doc = XDocument.Parse("""
                <?xml version="1.0" encoding="UTF-8"?>
                <DragonQuestX>
                    <PlayerList Version="0.9.0" LastSelect="0">
                    </PlayerList>
                </DragonQuestX>
                """);
        }

        var playerList = doc.XPathSelectElement("//DragonQuestX/PlayerList")!;
        playerList.Add(new XElement("Player",
            new XAttribute("Number", player.Number),
            new XAttribute("Token", player.Token)));

        File.WriteAllBytes(path, Encrypt(SerializeXml(doc)));
    }

    private static DqxTrialInfo? ReadTrialInfo(string folder)
    {
        var path = GetObfuscatedPath(folder);
        if (!File.Exists(path)) return null;

        var el = XDocument.Parse(Decrypt(File.ReadAllBytes(path)))
                          .XPathSelectElement("//TrialInfo");
        if (el == null) return null;

        var id    = el.Attribute("ID")?.Value;
        var token = el.Attribute("Token")?.Value;
        var code  = el.Attribute("Code")?.Value;

        return (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(token) || string.IsNullOrEmpty(code))
            ? null
            : new DqxTrialInfo { Id = id, Token = token, Code = code };
    }

    private static void UpdateTrialToken(string newToken, string folder)
    {
        var path = GetObfuscatedPath(folder);
        if (!File.Exists(path)) return;

        var doc = XDocument.Parse(Decrypt(File.ReadAllBytes(path)));
        var el  = doc.XPathSelectElement("//TrialInfo");
        if (el == null) return;

        el.SetAttributeValue("Token", newToken);
        File.WriteAllBytes(path, Encrypt(SerializeXml(doc)));
    }

    private static string GetObfuscatedPath(string folder) =>
        Path.Combine(folder, ObfuscateFilename("dqxPlayerList.xml", 0x11));

    private static string Decrypt(byte[] data) =>
        Encoding.UTF8.GetString(Xor(data));

    private static byte[] Encrypt(string xml) =>
        Xor(Encoding.UTF8.GetBytes(xml));

    private static void RemovePlayer(int number, string folder)
    {
        var path = GetObfuscatedPath(folder);
        if (!File.Exists(path)) return;

        var doc = XDocument.Parse(Decrypt(File.ReadAllBytes(path)));
        var entry = doc.XPathSelectElements("//Player")
            .FirstOrDefault(el => el.Attribute("Number")?.Value == number.ToString());
        if (entry == null) return;

        entry.Remove();
        File.WriteAllBytes(path, Encrypt(SerializeXml(doc)));
    }

    private static byte[] Xor(byte[] data)
    {
        var key = Crc32(Encoding.ASCII.GetBytes(Environment.UserName + "\0"));
        var result = new byte[data.Length];
        for (var i = 0; i < data.Length; i++)
        {
            var k = key[i % key.Length];
            var b = data[i];
            result[i] = (b != 0x00 && b != k) ? (byte)(b ^ k) : b;
        }
        return result;
    }

    private static string SerializeXml(XDocument doc)
    {
        var settings = new System.Xml.XmlWriterSettings
        {
            Indent = true,
            IndentChars = "\t",
            NewLineChars = "\n",
            NewLineHandling = System.Xml.NewLineHandling.Replace,
            Encoding = new UTF8Encoding(false),
        };
        using var ms = new MemoryStream();
        using (var writer = System.Xml.XmlWriter.Create(ms, settings))
            doc.Save(writer);
        return Encoding.UTF8.GetString(ms.ToArray())
            .Replace(" />", "/>")
            .Replace("utf-8", "UTF-8") + "\n";
    }

    // Non-standard CRC32: initial value 0, polynomial 0x04C11DB7, little-endian output.
    // This is the exact algorithm used by the original DQX launcher.
    private static byte[] Crc32(byte[] data)
    {
        const uint poly = 0x04C11DB7;
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            var c = i << 24;
            for (var j = 0; j < 8; j++)
                c = (c & 0x80000000) != 0 ? (c << 1) ^ poly : c << 1;
            table[i] = c;
        }
        uint crc = 0;
        foreach (var b in data)
            crc = (crc << 8) ^ table[((crc >> 24) ^ b) & 0xFF];
        return [(byte)(crc & 0xFF), (byte)((crc >> 8) & 0xFF),
                (byte)((crc >> 16) & 0xFF), (byte)((crc >> 24) & 0xFF)];
    }

    private static readonly string DigitMap = "&@#+(_-)]$";
    private static readonly int[] UpperMap =
    [
        0x03, 0x05, 0x14, 0x17, 0x08, 0x18, 0x06, 0x07,
        0x01, 0x12, 0x02, 0x09, 0x0A, 0x0C, 0x19, 0x0D,
        0x04, 0x0F, 0x15, 0x0E, 0x10, 0x00, 0x11, 0x0B,
        0x16, 0x13
    ];
    private static readonly int[] LowerMap =
    [
        0x12, 0x15, 0x04, 0x17, 0x0B, 0x19, 0x0D, 0x0E,
        0x03, 0x11, 0x0C, 0x10, 0x14, 0x05, 0x07, 0x0F,
        0x08, 0x06, 0x01, 0x09, 0x02, 0x0A, 0x16, 0x13,
        0x00, 0x18
    ];

    private static string ObfuscateFilename(string filename, int seed)
    {
        var checksum = seed & 0xFF;
        var sb = new StringBuilder();
        foreach (var ch in Path.GetFileName(filename))
        {
            char c;
            if (ch is >= '0' and <= '9')
                c = DigitMap[(checksum + (ch - '0')) % 10];
            else if (ch is >= 'A' and <= 'Z')
                c = (char)('A' + UpperMap[(checksum + (ch - 'A')) % 26]);
            else if (ch is >= 'a' and <= 'z')
                c = (char)('a' + LowerMap[(checksum + (ch - 'a')) % 26]);
            else if (ch == '.') c = '!';
            else if (ch == '*') c = '~';
            else c = ch;
            sb.Append(c);
            checksum = (checksum + ch) & 0xFF;
        }
        return sb.ToString();
    }
}
