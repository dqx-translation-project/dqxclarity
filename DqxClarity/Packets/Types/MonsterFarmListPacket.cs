using System.Buffers.Binary;
using System.Text;
using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

// The Monster Farm's deposit list -- monsters currently stored there, each
// with a player-assigned nickname. Up to 3 entries; the sample capture has
// all 3 filled (a u32 count field at Data offset 0x0C reads 3, matching).
//
// Same length-prefixed-cstring shape as MonsterTavernListPacket (see that
// class's doc comment for the full reasoning): every name in the sample is
// immediately preceded by its own u32 byte-length (utf-8 length including
// the null terminator), confirmed exact for all 3. That's the same shape
// EntityPacket already uses for Player/Party/Monster names, safe to grow or
// shrink freely since the client reads the length and advances by exactly
// that many bytes rather than assuming a fixed offset for whatever follows.
// Same caveat as MonsterTavernListPacket applies: this is an architectural
// inference from the length prefix, not crash-tested against a live
// capture -- if a translated name here ever crashes or corrupts the
// client, it needs the fixed-width-slot treatment instead.
//
// Approach: identical byte scan to MonsterTavernListPacket -- look for
// every `[u32 length][utf-8 bytes][0x00]` where the utf-8 bytes are a
// single, complete, maximal Japanese run (JapaneseRunLength) exactly
// `length - 1` bytes long.
//
// Name resolution: local_player_names m00 dict first, then
// custom_npc_name_overrides m00 dict, romanizer fallback if neither has a
// match.
//
// Sample: docs/packets/references/monster_farm_list (3/3 slots filled)
public sealed class MonsterFarmListPacket : IPacket
{
    private const int MinNameLength = 4;   // 1 utf-8 byte + null terminator, generous floor
    private const int MaxNameLength = 128; // generous ceiling; longest seen in sample was 16

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    public byte[]? ModifiedData { get; private set; }

    public MonsterFarmListPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
    }

    public void Build()
    {
        var playerDict = _deps.M00Dict("local_player_names");
        var overrideDict = _deps.M00Dict("custom_npc_name_overrides");
        var changed = false;
        var writer = new PacketWriter();

        var i = 0;
        while (i < _raw.Length)
        {
            if (TryReadNameField(_raw, i, out var fieldLen, out var text))
            {
                var newName = ResolveName(text, playerDict, overrideDict, _deps.Romanizer);
                if (newName != text)
                {
                    changed = true;
                    var newBytes = Encoding.UTF8.GetBytes(newName);
                    writer.WriteU32((uint)(newBytes.Length + 1)); // +1 for null terminator
                    writer.WriteBytes(newBytes);
                    writer.WriteU8(0);
                }
                else
                {
                    writer.WriteBytes(_raw.AsSpan(i, 4 + fieldLen).ToArray());
                }

                i += 4 + fieldLen;
            }
            else
            {
                writer.WriteU8(_raw[i]);
                i++;
            }
        }

        if (!changed) return;
        ModifiedData = writer.Build();
    }

    // Recognises `[u32 length][name bytes][0x00]` starting at `start`, where
    // `length` is the name's utf-8 byte count including the null terminator
    // and the name bytes are a single, complete, maximal Japanese run (see
    // class doc comment). `fieldLen` on success is `length` (i.e. name bytes
    // + null, NOT including the 4-byte length prefix itself).
    private static bool TryReadNameField(byte[] data, int start, out int fieldLen, out string text)
    {
        fieldLen = 0;
        text = "";

        if (start + 4 > data.Length) return false;
        var length = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(start, 4));
        if (length < MinNameLength || length > MaxNameLength) return false;

        var nameStart = start + 4;
        if (nameStart + length > data.Length) return false;

        var strBytes = (int)length - 1; // minus null terminator
        if (strBytes <= 0) return false;
        if (data[nameStart + strBytes] != 0) return false;

        var runLen = JapaneseRunLength(data, nameStart);
        if (runLen != strBytes) return false;

        text = Encoding.UTF8.GetString(data, nameStart, strBytes);
        fieldLen = (int)length;
        return true;
    }

    // Finds the length, in bytes, of the maximal run starting at `start`
    // made up entirely of valid 3-byte UTF-8 sequences that decode into the
    // hiragana/katakana/common-kanji ranges. Returns 0 if `start` isn't the
    // beginning of such a run.
    private static int JapaneseRunLength(byte[] data, int start)
    {
        var i = start;
        while (i + 3 <= data.Length)
        {
            var b0 = data[i];
            var b1 = data[i + 1];
            var b2 = data[i + 2];
            if ((b0 & 0xF0) != 0xE0) break;                     // not a 3-byte utf-8 lead byte
            if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) break; // invalid continuation bytes
            var codepoint = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
            if (!IsJapaneseCodepoint(codepoint)) break;
            i += 3;
        }
        return i - start;
    }

    private static bool IsJapaneseCodepoint(int codepoint) =>
        (codepoint >= 0x3040 && codepoint <= 0x30FF) || // hiragana + katakana
        (codepoint >= 0x4E00 && codepoint <= 0x9FFF);   // common kanji

    // local_player_names first, then custom_npc_name_overrides, romanizer
    // fallback if neither has a match.
    private static string ResolveName(string japanese, Dictionary<string, string> playerDict, Dictionary<string, string> overrideDict, IRomanizer romanizer)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;
        if (playerDict.TryGetValue(japanese, out var knownPlayer) && !string.IsNullOrEmpty(knownPlayer)) return knownPlayer;
        if (overrideDict.TryGetValue(japanese, out var knownOverride) && !string.IsNullOrEmpty(knownOverride)) return knownOverride;
        return romanizer.ToRomaji(japanese);
    }
}
