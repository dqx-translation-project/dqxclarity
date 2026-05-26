using System.Text;

namespace DqxClarity.Packets.Types;

//

// The payload is opaque — we don't parse fields. We do raw utf-8 byte
// replacements for known japanese server-name strings, padding the english
// replacement with trailing nulls to match the original byte length and avoid
// disturbing the surrounding wire format.
public sealed class ServerListPacket : IPacket
{
    // Maps source jp name -> target en name. Order matters only when a key is a
    // prefix of another (none of these collide today, but order is preserved to keep behaviour identical).
    private static readonly (string Jp, string En)[] Servers =
    {
        ("サーバー０１", "Server 01"),
        ("サーバー０２", "Server 02"),
        ("サーバー０３", "Server 03"),
        ("サーバー０４", "Server 04"),
        ("サーバー０５", "Server 05"),
        ("サーバー０６", "Server 06"),
        ("サーバー０７", "Server 07"),
        ("サーバー０８", "Server 08"),
        ("サーバー０９", "Server 09"),
        ("サーバー１０", "Server 10"),
        ("サーバー１１", "Server 11"),
        ("サーバー１２", "Server 12"),
        ("サーバー１３", "Server 13"),
        ("サーバー１４", "Server 14"),
        ("サーバー１５", "Server 15"),
        ("サーバー１６", "Server 16"),
        ("サーバー１７", "Server 17"),
        ("サーバー１８", "Server 18"),
        ("サーバー１９", "Server 19"),
        ("サーバー２０", "Server 20"),
        ("サーバー２１", "Server 21"),
        ("サーバー２２", "Server 22"),
        ("サーバー２３", "Server 23"),
        ("サーバー２４", "Server 24"),
        ("サーバー２５", "Server 25"),
        ("サーバー２６", "Server 26"),
        ("サーバー２７", "Server 27"),
        ("サーバー２８", "Server 28"),
        ("サーバー２９", "Server 29"),
        ("サーバー３０", "Server 30"),
        ("サーバー３１", "Server 31"),
        ("サーバー３２", "Server 32"),
        ("サーバー３３", "Server 33"),
        ("サーバー３４", "Server 34"),
        ("サーバー３５", "Server 35"),
        ("サーバー３６", "Server 36"),
        ("サーバー３７", "Server 37"),
        ("サーバー３８", "Server 38"),
        ("サーバー３９", "Server 39"),
        ("サーバー４０", "Server 40"),
        ("［オ］住宅村", "O Housing"),
        ("イベント会場", "Event"),
        ("魔法の迷宮",   "Mag. Maze"),
        ("ＰＴ同盟空間", "Alliance"),
        ("［ウ］住宅村", "W Housing"),
        ("［エ］住宅村", "E Housing"),
        ("［ド］住宅村", "D Housing"),
        ("［プ］住宅村", "P Housing"),
        ("コロシアム",   "Coliseum"),
        ("カジノ",        "Casino"),
        ("特殊エリア",   "Special"),
        ("強戦士の間",   "Boss Book"),
        ("王家の迷宮",   "Roy. Maze"),
        ("クイズエリア", "Quiz Area"),
        ("バトルロード", "Btl. Road"),
        ("不思議の魔塔", "M. Tower"),
        ("幻想画エリア", "Painting"),
        ("［レ］住宅村", "L Housing"),
        ("竜王の城",     "DQ1 Event"),
        ("学園特殊室内", "Classroom"),
        ("学園教練区域", "Drill"),
        ("ゾーマの城",   "DQ3 Event"),
        ("バトエン",     "Batoen"),
        ("大富豪",       "Tycoon"),
        ("防衛軍エリア", "ADF"),
        ("謎の遺跡島内", "Zelmea"),
        ("プレイエリア", "Play Area"),
        ("マイタウン",   "My Town"),
        ("万魔の塔",     "Banma"),
        ("源世庫エリア", "Panigalm"),
        ("咎人エリア",   "Criminals"),
        ("訓練場エリア", "Training"),
        ("アスタルジア", "Astalgia"),
        ("劇場\x00\x00\x00", "Theatre"),
    };

    private readonly byte[] _raw;

    public byte[]? ModifiedData { get; private set; }

    public ServerListPacket(byte[] payloadData, PacketDependencies _) { _raw = payloadData; }

    public void Build()
    {
        var working = _raw;
        var anyChange = false;
        foreach (var (jp, en) in Servers)
        {
            var jpBytes = Encoding.UTF8.GetBytes(jp);
            var enBytes = PadEnglish(jpBytes, en);
            if (TryReplace(ref working, jpBytes, enBytes))
                anyChange = true;
        }
        if (anyChange) ModifiedData = working;
    }

    // Pads en's utf-8 bytes with 0x00 up to jp's byte length, so the substituted
    // run never shrinks. Truncates if en is longer (defensive; doesn't happen
    // for the current table).
    private static byte[] PadEnglish(byte[] jpBytes, string en)
    {
        var enBytes = Encoding.UTF8.GetBytes(en);
        if (enBytes.Length == jpBytes.Length) return enBytes;
        if (enBytes.Length > jpBytes.Length) return enBytes[..jpBytes.Length];
        var padded = new byte[jpBytes.Length];
        Buffer.BlockCopy(enBytes, 0, padded, 0, enBytes.Length);
        return padded;
    }

    private static bool TryReplace(ref byte[] buf, byte[] needle, byte[] replacement)
    {
        var found = false;
        var output = new List<byte>(buf.Length);
        var i = 0;
        while (i < buf.Length)
        {
            if (i + needle.Length <= buf.Length && buf.AsSpan(i, needle.Length).SequenceEqual(needle))
            {
                output.AddRange(replacement);
                i += needle.Length;
                found = true;
            }
            else
            {
                output.Add(buf[i]);
                i++;
            }
        }
        if (found) buf = output.ToArray();
        return found;
    }
}
