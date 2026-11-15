namespace DqxClarity.Translation;

// Shared "title + kana name" handling for generated My Town / map NPC names,
// used by MyTownAmenityPacket and MapNpcListPacket (the map's NPC list).
//
// Most of these names follow a template: a fixed job title followed by a
// player-chosen kana name (紹介人ショウブ = 紹介人 "Introducer" + ショウブ).
// When a name starts with a known title and the rest is kana only, the title
// comes from the table below and the rest is romanized:
//   紹介人ショウブ -> "Introducer " + romaji(ショウブ)
// Anything else (no known title, or kanji after the title -- the romanizer
// leaves kanji untouched) returns null so the caller can fall back.
public static class MyTownNameTemplate
{
    // Japanese title -> English. Checked longest first, so a longer title is
    // never cut short by a shorter one that happens to prefix it.
    private static readonly (string Ja, string En)[] Titles =
        new (string Ja, string En)[]
        {
            ("紹介人",     "Introducer"),
            ("シスター・", "Sister"),
            ("神官",       "Priest"),
            ("魚交換員",   "Fish Exchange"),
            ("住宅素材屋", "Housing Materials"),
            ("魔物管理人", "Monster Manager"),
            ("取引商",     "Trader"),
            ("案内係",     "Guide"),
            ("住宅商",     "Realtor"),
            ("預かり所",   "Storage"),
            ("郵便局員",   "Postman"),
            ("神父",       "Father"),
        }
        .OrderByDescending(t => t.Ja.Length)
        .ToArray();

    public static string? TryTranslate(string name, IRomanizer romanizer, int romajiCap)
    {
        foreach (var (ja, enTitle) in Titles)
        {
            if (!name.StartsWith(ja, StringComparison.Ordinal)) continue;

            var rest = name[ja.Length..];
            if (rest.Length == 0 || !rest.All(IsKana)) return null;

            var romaji = romanizer.ToRomaji(rest, romajiCap);
            if (string.IsNullOrWhiteSpace(romaji) || Translator.IsTextJapanese(romaji)) return null;

            return $"{enTitle} {romaji}";
        }
        return null;
    }

    // Hiragana, katakana (incl. ー and ・), and half-width katakana.
    private static bool IsKana(char c) =>
        c is (>= '぀' and <= 'ゟ') or (>= '゠' and <= 'ヿ') or (>= 'ｦ' and <= 'ﾟ');
}
