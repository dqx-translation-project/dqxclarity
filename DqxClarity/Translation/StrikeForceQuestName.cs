namespace DqxClarity.Translation;

// Strike Force quest names. These quests come down from the server rather than
// from the client's local files, so no entry exists for them in any quest
// dictionary -- but they always follow one pattern:
//
//     <japanese monster name>討伐！    ->    Hunt <english monster name>!
//
// e.g. 暴君バサグランデ強討伐！ is the monster 暴君バサグランデ強 followed by
// 討伐！ ("defeat!"), and こうていタップ討伐！ is こうていタップ + 討伐！. The
// monster half is looked up in the m00 'monsters' dictionary (the same one
// EntityPacket uses for monster nameplates); the rest is fixed.
//
// Used by StrikeForceQuestNamePacket (0x5D 0x374A) and by QuestPacket's
// quest-name field (Quest Log / Quest Accept / Quest Map Open), where it is
// only tried after the normal 'quests' lookup misses. It matches the WHOLE
// name (suffix 討伐！ with a non-empty monster name in front), so a name that
// isn't one of these quests never matches and is left alone.
public static class StrikeForceQuestName
{
    // Full-width exclamation mark, exactly as the server sends it.
    private const string Suffix = "討伐！";

    // Returns "Hunt <english>!" on a match, or null when the name isn't of the
    // pattern or the monster isn't in the dictionary (caller leaves the
    // japanese in place -- no machine translation, no romaji).
    public static string? Translate(string name, IReadOnlyDictionary<string, string> monsters)
    {
        if (string.IsNullOrEmpty(name)) return null;
        if (!name.EndsWith(Suffix, StringComparison.Ordinal)) return null;

        var monster = name[..^Suffix.Length];
        if (monster.Length == 0) return null;

        if (!monsters.TryGetValue(monster, out var english) || string.IsNullOrEmpty(english)) return null;

        return "Hunt " + english + "!";
    }
}
