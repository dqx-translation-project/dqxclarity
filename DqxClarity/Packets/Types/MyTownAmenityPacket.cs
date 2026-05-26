using DqxClarity.Translation;

namespace DqxClarity.Packets.Types;

//

// Layout (after opcode + marker):
//   header_data  12 bytes (passthrough)
//   name         cstring (utf-8)
//
// Same lookup-then-romanize fallback as ConciergePacket, but with a 25-char
// romaji cap.
//
// wanakana converts kana only — kanji passes through unchanged. names that
// contain kanji will produce mixed-script output from the romanizer and are
// blocked by the IsTextJapanese guard in Build(); they need a hard dict entry
// in custom_concierge_mail_names or local_mytown_names to translate.
public sealed class MyTownAmenityPacket : IPacket
{
    private const int HeaderBytes = 12;
    private const int RomajiCap = 25;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _name = "";

    public byte[]? ModifiedData { get; private set; }

    public MyTownAmenityPacket(byte[] payloadData, PacketDependencies deps)
    {
        _raw = payloadData;
        _deps = deps;
        Parse();
    }

    private void Parse()
    {
        var reader = new PacketReader(_raw);
        _header = reader.ReadBytes(HeaderBytes).ToArray();
        _name = reader.ReadCString();
    }

    public void Build()
    {
        var dict = _deps.M00Dict("custom_concierge_mail_names", "local_mytown_names");
        var translated = dict.TryGetValue(_name, out var en) && !string.IsNullOrEmpty(en)
            ? en
            : _deps.Romanizer.ToRomaji(_name, RomajiCap);

        if (translated == _name || Translator.IsTextJapanese(translated)) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(translated);
        ModifiedData = writer.Build();
    }
}
