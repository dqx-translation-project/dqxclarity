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
//
// Exception: most amenity names follow a "title + kana name" template
// (紹介人ショウブ = 紹介人 "Introducer" + ショウブ). When the dicts miss and the
// name starts with one of the known titles and the rest is kana only,
// the title is translated from the table in MyTownNameTemplate (shared with
// MapNpcListPacket, the map's NPC list) and the rest is romanized:
// 紹介人ショウブ -> "Introducer " + romaji(ショウブ). Lookup order:
//   1. exact dict entry (custom_concierge_mail_names, local_mytown_names)
//   2. title template
//   3. whole-name romaji (kana-only names)
// Hardening (2026-11): the name is read with ReadCStringStrict (a moved field
// makes PacketGuard pass the packet through and file a mismatch report instead
// of translating whatever is there), and any bytes after the name are now kept
// -- an earlier version silently dropped them.
public sealed class MyTownAmenityPacket : IPacket
{
    private const int HeaderBytes = 12;
    private const int RomajiCap = 25;

    private readonly byte[] _raw;
    private readonly PacketDependencies _deps;

    private byte[] _header = Array.Empty<byte>();
    private string _name = "";
    private byte[] _remainder = Array.Empty<byte>();

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
        _header = reader.ReadBytesStrict(HeaderBytes, "amenity header").ToArray();
        PacketText.RequireFieldBoundary(_raw, HeaderBytes, "amenity name");
        _name = reader.ReadCStringStrict("amenity name", 256);
        reader.ExpectEnd("amenity"); // the name is the last field in the capture
        _remainder = reader.RemainingBytes().ToArray(); // kept: nothing follows in the captures, but never drop it
    }

    public void Build()
    {
        var dict = _deps.M00Dict("custom_concierge_mail_names", "local_mytown_names");
        var translated = dict.TryGetValue(_name, out var en) && !string.IsNullOrEmpty(en)
            ? en
            : MyTownNameTemplate.TryTranslate(_name, _deps.Romanizer, RomajiCap)
              ?? _deps.Romanizer.ToRomaji(_name, RomajiCap);

        if (translated == _name || Translator.IsTextJapanese(translated)) return;

        var writer = new PacketWriter();
        writer.WriteBytes(_header);
        writer.WriteCString(translated);
        writer.WriteBytes(_remainder);
        ModifiedData = writer.Build();
    }
}
