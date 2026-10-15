using System.Text;
using System.Text.RegularExpressions;
using DqxClarity.Translation;

namespace DqxClarity.Packets;

// Translates the server-built "system lines" that appear in the quest-progress
// message (QuestProgressPacket, 0x21 0x1305) and the green system message log
// (GreenSystemMessagePacket, 0x1F 0x8C41). Both carry the same family of
// fixed-template japanese lines, so the matching lives here once and both
// packets call it. Every line is either a fixed string or one of a handful of
// templates, rebuilt in english from dictionary lookups:
//
//   Fixed lines (checked first)
//     Lines that never change are plain entries in m00 'custom_corner_text'
//     (a whole-line exact match on the japanese), tried before any template.
//     A hit is used as written; because it is checked first, an entry also
//     overrides what a template would have produced for the same line.
//     <pnplacehold> / <snplacehold> in an entry are filled in with the active
//     character's names by the m00 loader, like every other m00 dictionary.
//
//   Defeat monsters
//     ja: <monster>討伐 <defeated>匹目！ 残り <remaining>匹
//         こうていタップ討伐 9匹目！ 残り 16匹
//     en: Defeated <defeated> <monster>! (<remaining> Left)
//         monster from m00 'monsters'
//
//   Defeat monsters with a skill / spell
//     ja: <skill>を使って <monster>討伐 <defeated>匹目！ 残り <remaining>匹
//         ドルマを使って バアラック討伐 1匹目！ 残り 2匹
//     en: Defeated <defeated> <monster> with <skill>! (<remaining> Left)
//         monster from m00 'monsters'; skill from the main glossary (the
//         'glossary' table in clarity_dialog.db -- there are no skill/spell
//         dictionaries in m00), looked up by exact japanese key
//
//   Collect items
//     ja: <item>を <collected>個 手に入れた！ 残り <remaining>個
//         メルサン小麦を 2個 手に入れた！ 残り 3個
//     en: Received <collected> <item>! (<remaining> Left)
//         item from m00 'items', then 'key_items'
//         (no capture of this one yet -- built from the template alone)
//
//   Acquire items (no "remaining" count)
//     ja: <item>を <number>枚 かくとく！      (個 also accepted)
//         ちいさなメダルを 1枚 かくとく！
//     en: Received <number> <item>!
//     ja: <item>を 手に入れた！
//         はぐメタチケットを 手に入れた！
//     en: Received <item>!
//         item from m00 'items', then 'key_items', as above
//
//   A player collects items
//     ja: <player>は <item>を <number>個 手に入れた！
//         ショウブは 海神のうろこを ３個 手に入れた！
//     en: <player> received <number> <item>!
//         player as in "Use an item" below. item from m00 'items', then
//         'key_items', and if neither has it, the main glossary. (Unlike the
//         "Collect items" line above, this has no 残り count.)
//
//   Chests transforming
//     ja: 宝箱<old>つが 光る宝箱<new>つに　変化した！
//         宝箱１つが 光る宝箱２つに　変化した！
//     en: The <old> chest(s) transform into <new> shiny chests!
//         singular/plural follows the counts: "The 1 chest transforms into
//         2 shiny chests!", "The 2 chests transform into 1 shiny chest!"
//
//   Shiny chests transforming
//     ja: 光る宝箱<first>つが 光る宝箱<second>つに 変化した！
//         光る宝箱２つが 光る宝箱３つに 変化した！
//     en: <first> shiny chest(s) transform into <second> shiny chest(s)!
//         singular/plural follows each count: "1 shiny chest transforms into
//         2 shiny chests!", "2 shiny chests transform into 1 shiny chest!"
//
//   Mirror reveals a room
//     ja: <mirror>が 左から<first>列目 上から<second>列目の部屋を 映し出した！
//         ふしぎな三面鏡が 左から2列目 上から1列目の部屋を 映し出した！
//     en: The Mirror reveals the room that's <first> left, <second> down!
//         <mirror> is either ふしぎな水鏡 or ふしぎな三面鏡 and isn't used in
//         the english
//
//   Mage Duster absorbing MP
//     ja: メイジダスターに <absorbed>ＭＰ ためた！ 残り <remaining>ＭＰ
//         メイジダスターに 16ＭＰ ためた！ 残り 10ＭＰ
//     en: The Mage Duster has <absorbed> MP absorbed! (<remaining> MP Left)
//         the "ＭＰ" is full-width in the japanese, as the server sends it
//
//   Running out of an item
//     ja: <item>が なくなった！
//         海神のうろこが なくなった！
//     en: Ran out of <item>!
//         item from m00 'items', then 'key_items', then the main glossary
//
//   Use items (with a number)
//     ja: <player>は <item>を <number>個 使った！
//         ショウブは 海神のうろこを １個 使った！
//     en: <player> uses <number> <item>!
//         player and item exactly as in "A player collects items" above
//         (player: local_player_names, custom_npc_name_overrides, romaji;
//         item: items, key_items, then the main glossary)
//
//   Use an item
//     ja: <player>は <item>を使った！
//         ショウブは ゼルメアの聖紋を使った！
//     en: <player> uses <item>!
//         item as above; player from m00 'local_player_names', then
//         'custom_npc_name_overrides' (a party member rather than a player),
//         then romaji. The player name is free text and may itself contain は,
//         so every は is tried as the split point, left to right, and the
//         first one whose right-hand side is a known item wins.
//
// Matching is on the whole line, tolerant of the spacing around each part, and
// whole-or-nothing: if the line doesn't match a template, or any name it needs
// (monster, item or skill) isn't in its dictionary, the packet is left
// untouched and the japanese shows. No machine translation, no romaji. Numbers
// may be full-width and are written back as plain digits.
public sealed class SystemLineTranslator
{
    private const string Num = @"[0-9０-９]+";

    // Whole-line templates. Spaces in the japanese are matched loosely (\s*)
    // since the server's spacing is the only thing separating the parts.
    private static readonly Regex MonsterRe = new(
        @"^(?<monster>.+?)討伐\s*(?<defeated>" + Num + @")匹目！\s*残り\s*(?<remaining>" + Num + @")匹$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SkillMonsterRe = new(
        @"^(?<skill>.+?)を使って\s*(?<monster>.+?)討伐\s*(?<defeated>" + Num + @")匹目！\s*残り\s*(?<remaining>" + Num + @")匹$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // Acquire forms with no "remaining" count.
    private static readonly Regex AcquireAmountRe = new(
        @"^(?<item>.+?)を\s*(?<amount>" + Num + @")(?:個|枚)\s*かくとく！$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex AcquireRe = new(
        @"^(?<item>.+?)を\s*手に入れた！$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // "<player>は <item>を使った！" -- split by hand in TryUseItem (see there).
    private const string UsedSuffix = "を使った！";

    // "<player>は <item>を <number>個 手に入れた！" -- head ("<player>は <item>")
    // is split by hand in TrySplitPlayerItem.
    private static readonly Regex PlayerCollectedRe = new(
        @"^(?<head>.+?)を\s*(?<amount>" + Num + @")個\s*手に入れた！$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // "<player>は <item>を <number>個 使った！" -- head split by hand in
    // TrySplitPlayerItem, like PlayerCollectedRe.
    private static readonly Regex PlayerUsedAmountRe = new(
        @"^(?<head>.+?)を\s*(?<amount>" + Num + @")個\s*使った！$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // The space before 変化した！ is a full-width one (\s covers it).
    private static readonly Regex ChestsRe = new(
        @"^宝箱(?<old>" + Num + @")つが\s*光る宝箱(?<new>" + Num + @")つに\s*変化した！$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // Same, but the first chest is already a shiny one.
    private static readonly Regex ShinyChestsRe = new(
        @"^光る宝箱(?<first>" + Num + @")つが\s*光る宝箱(?<second>" + Num + @")つに\s*変化した！$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // "<mirror>が 左から<n>列目 上から<n>列目の部屋を 映し出した！"
    private static readonly Regex MirrorRe = new(
        @"^ふしぎな(?:水鏡|三面鏡)が\s*左から\s*(?<left>" + Num + @")列目\s*上から\s*(?<down>" + Num + @")列目の部屋を\s*映し出した！$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // "ＭＰ" is full-width, exactly as the server sends it.
    private static readonly Regex MageDusterRe = new(
        @"^メイジダスターに\s*(?<absorbed>" + Num + @")ＭＰ\s*ためた！\s*残り\s*(?<remaining>" + Num + @")ＭＰ$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex RanOutRe = new(
        @"^(?<item>.+?)が\s*なくなった！$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex ItemRe = new(
        @"^(?<item>.+?)を\s*(?<collected>" + Num + @")個\s*手に入れた！\s*残り\s*(?<remaining>" + Num + @")個$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly PacketDependencies _deps;

    public SystemLineTranslator(PacketDependencies deps)
    {
        _deps = deps;
    }

    // Fixed lines first, then the templates. Null when nothing matches or a
    // name can't be resolved.
    public string? Translate(string text) => FixedLine(text) ?? Templates(text);

    // Fixed lines: exact whole-line entries in custom_corner_text.
    public string? FixedLine(string text)
    {
        var fixedLines = _deps.M00Dict("custom_corner_text");
        return fixedLines.TryGetValue(text, out var fixedEnglish) && !string.IsNullOrEmpty(fixedEnglish)
            ? fixedEnglish
            : null;
    }

    // The templates, tried in order. Null when none matches or a name it needs
    // can't be resolved.
    public string? Templates(string text)
    {
        // Skill template first: it also contains the plain monster template as
        // its second half, but not the other way round.
        var m = SkillMonsterRe.Match(text);
        if (m.Success)
        {
            var monster = LookupMonster(m.Groups["monster"].Value);
            var skill = LookupGlossary(m.Groups["skill"].Value);
            if (monster == null || skill == null) return null;
            return $"Defeated {Digits(m, "defeated")} {monster} with {skill}! ({Digits(m, "remaining")} Left)";
        }

        m = MonsterRe.Match(text);
        if (m.Success)
        {
            var monster = LookupMonster(m.Groups["monster"].Value);
            if (monster == null) return null;
            return $"Defeated {Digits(m, "defeated")} {monster}! ({Digits(m, "remaining")} Left)";
        }

        m = ItemRe.Match(text);
        if (m.Success)
        {
            var item = LookupItem(m.Groups["item"].Value);
            if (item == null) return null;
            return $"Received {Digits(m, "collected")} {item}! ({Digits(m, "remaining")} Left)";
        }

        m = AcquireAmountRe.Match(text);
        if (m.Success)
        {
            var item = LookupItem(m.Groups["item"].Value);
            if (item == null) return null;
            return $"Received {Digits(m, "amount")} {item}!";
        }

        m = AcquireRe.Match(text);
        if (m.Success)
        {
            var item = LookupItem(m.Groups["item"].Value);
            if (item == null) return null;
            return $"Received {item}!";
        }

        m = PlayerCollectedRe.Match(text);
        if (m.Success)
        {
            var collected = TrySplitPlayerItem(m.Groups["head"].Value, "received", Digits(m, "amount"));
            if (collected != null) return collected;
        }

        m = PlayerUsedAmountRe.Match(text);
        if (m.Success)
        {
            var used = TrySplitPlayerItem(m.Groups["head"].Value, "uses", Digits(m, "amount"));
            if (used != null) return used;
        }

        m = ChestsRe.Match(text);
        if (m.Success)
        {
            var oldCount = Digits(m, "old");
            var newCount = Digits(m, "new");
            var oldChests = oldCount == "1" ? "chest transforms" : "chests transform";
            var newChests = newCount == "1" ? "chest" : "chests";
            return $"The {oldCount} {oldChests} into {newCount} shiny {newChests}!";
        }

        m = ShinyChestsRe.Match(text);
        if (m.Success)
        {
            var first = Digits(m, "first");
            var second = Digits(m, "second");
            var firstChests = first == "1" ? "chest transforms" : "chests transform";
            var secondChests = second == "1" ? "chest" : "chests";
            return $"{first} shiny {firstChests} into {second} shiny {secondChests}!";
        }

        m = MirrorRe.Match(text);
        if (m.Success)
            return $"The Mirror reveals the room that's {Digits(m, "left")} left, {Digits(m, "down")} down!";

        m = MageDusterRe.Match(text);
        if (m.Success)
            return $"The Mage Duster has {Digits(m, "absorbed")} MP absorbed! ({Digits(m, "remaining")} MP Left)";

        m = RanOutRe.Match(text);
        if (m.Success)
        {
            var item = LookupItem(m.Groups["item"].Value) ?? LookupGlossary(m.Groups["item"].Value);
            if (item != null) return $"Ran out of {item}!";
        }

        return TryUseItem(text);
    }

    // "<player>は <item>" + a verb and an amount -> "<player> <verb> <amount>
    // <item>!" (received / uses). Same split rule as TryUseItem: every は is
    // tried left to right and the first whose right-hand side resolves as an
    // item wins. Here the item also falls back to the main glossary when
    // items / key_items miss.
    private string? TrySplitPlayerItem(string head, string verb, string amount)
    {
        for (var i = 1; i < head.Length - 1; i++)
        {
            if (head[i] != 'は') continue;

            var ja = head[(i + 1)..].Trim();
            var item = LookupItem(ja) ?? LookupGlossary(ja);
            if (item == null) continue;

            var player = ResolvePlayerName(head[..i].Trim());
            if (string.IsNullOrEmpty(player)) continue;
            return $"{player} {verb} {amount} {item}!";
        }
        return null;
    }

    // "<player>は <item>を使った！" -> "<player> uses <item>!". Whole-or-nothing
    // like the rest: null unless the line ends in を使った！ and the part after
    // some は is a known item.
    private string? TryUseItem(string text)
    {
        if (!text.EndsWith(UsedSuffix, StringComparison.Ordinal)) return null;
        var body = text[..^UsedSuffix.Length];

        for (var i = 1; i < body.Length - 1; i++)
        {
            if (body[i] != 'は') continue;

            var item = LookupItem(body[(i + 1)..].Trim());
            if (item == null) continue;

            var player = ResolvePlayerName(body[..i].Trim());
            if (string.IsNullOrEmpty(player)) continue;
            return $"{player} uses {item}!";
        }
        return null;
    }

    // Custom player names first, then custom party-member (npc) overrides, then
    // romaji.
    private string ResolvePlayerName(string japanese)
    {
        if (string.IsNullOrEmpty(japanese) || !Translator.IsTextJapanese(japanese)) return japanese;

        var playerDict = _deps.M00Dict("local_player_names");
        if (playerDict.TryGetValue(japanese, out var player) && !string.IsNullOrEmpty(player)) return player;

        var overrideDict = _deps.M00Dict("custom_npc_name_overrides");
        if (overrideDict.TryGetValue(japanese, out var custom) && !string.IsNullOrEmpty(custom)) return custom;

        return _deps.Romanizer.ToRomaji(japanese);
    }

    private string? LookupMonster(string ja) => Lookup(_deps.M00Dict("monsters"), ja);

    // items first, then key_items (key_items are only consulted on an items miss).
    private string? LookupItem(string ja) =>
        Lookup(_deps.M00Dict("items"), ja) ?? Lookup(_deps.M00Dict("key_items"), ja);

    // Skills and spells have no m00 dictionary; they live in the main glossary.
    // Exact japanese key, read straight from the glossary table.
    private string? LookupGlossary(string ja)
    {
        var en = _deps.Db.Read(ja, "glossary")?.Trim();
        return string.IsNullOrEmpty(en) ? null : en;
    }

    private static string? Lookup(Dictionary<string, string> dict, string ja) =>
        dict.TryGetValue(ja, out var en) && !string.IsNullOrEmpty(en) ? en : null;

    // Captured number as plain ascii digits (handles full-width).
    private static string Digits(Match m, string group) =>
        m.Groups[group].Value.Normalize(NormalizationForm.FormKC)
            .Trim()
            .TrimStart('0') is { Length: > 0 } s ? s : "0";
}
