using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DqxClarity.Launcher.Services;

public class GameLaunchService
{
    [DllImport("winmm.dll", EntryPoint = "timeGetTime")]
    private static extern uint GetTime();

    private static readonly char[] SqEx = "SqEx".ToCharArray();

    /// <summary>
    /// Launch DQXGame.exe directly, bypassing the native DQXBoot launcher.
    /// </summary>
    public void Launch(string installDir, string sessionId, int playerNumber = 1)
    {
        var gamePath = Path.Combine(installDir, "Game", "DQXGame.exe");
        if (!File.Exists(gamePath))
            throw new FileNotFoundException($"DQXGame.exe not found at {gamePath}");

        var args = $"-StartupToken={GetStartupToken()} " +
                   $"-SessionID={EncodeSessionId(sessionId)} " +
                   $"-PlayerNumber={playerNumber} " +
                   $"-USE_APARTMENTTHREADED";

        var psi = new ProcessStartInfo(gamePath)
        {
            WorkingDirectory = Path.Combine(installDir, "Game"),
            UseShellExecute = false,
            Arguments = args,
        };
        Process.Start(psi);
    }

    /// <summary>
    /// Encode a 56-character hex session ID into the 64-byte token DQXGame.exe expects.
    /// The encoding is time-based (per-minute) so calling this twice in the same minute
    /// produces the same output.
    /// </summary>
    public static string EncodeSessionId(string sid)
    {
        if (!Regex.IsMatch(sid, "^[0-9a-fA-F]{56}$"))
            throw new ArgumentException("SessionId must be a 56-character hex string.", nameof(sid));

        var timeMinutes = (DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60).ToString();
        var input = $"DQUEST10{sid}";  // 8 + 56 = 64 chars
        var md5 = MD5.HashData(Encoding.UTF8.GetBytes($"{timeMinutes}DraqonQuestX"));

        var output = new byte[64];
        for (var i = 0; i < 64; i++)
        {
            int ecx = md5[i % 16];
            var eax = i < input.Length ? (int)input[i] : 0;
            ecx -= 48;
            eax += ecx;
            eax %= 78;
            eax += 48;
            output[i] = (byte)eax;
        }

        return Encoding.UTF8.GetString(output);
    }

    // The official launcher uses an MT RNG for these 4 chars, but the server can't validate them,
    // so we stuff 0000 in — matching GalapaLauncher's approach.
    private static string GetStartupToken()
    {
        var baseString = "0000" + (GetTime() >>> 1);
        return new string(baseString
            .ToCharArray()
            .Select((c, i) => (char)(c ^ SqEx[i & 3]))
            .ToArray());
    }
}
