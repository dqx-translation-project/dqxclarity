namespace DqxClarity.Packets;

// Port of main branch player.py's _load_story_so_far_into_db /
// _load_fixed_dialog_into_db / _update_m00_table / _write_player. Main ran
// this once at login, driven by a Frida hook's init_player message. This
// branch has no such event, so PlayerContext calls it instead whenever it
// resolves (or re-resolves, e.g. switching to an alt mid-session) which
// character is active -- see PlayerContext's doc comment for how that's
// determined without a hook.
//
// The job itself is unchanged from main: template tables
// (story_so_far_template, fixed_dialog_template) are pre-authored generically
// with <pnplacehold>/<snplacehold>/<kyodai_rel1-3> tokens in place of the
// player's actual name/sibling name/relationship word, because the community
// translation server has no idea who's playing. This substitutes the current
// player's specific text into those tokens and writes the result into the
// tables packets actually query at runtime (story_so_far, dialog,
// bad_strings) -- so that when e.g. StorySoFarTextPacket looks up raw wire
// text that embeds the player's literal name, there's finally a row to find.
//
// m00_strings (the mail/dialogue dictionary PacketDependencies.M00Dict hands
// out) is handled differently on purpose: it does NOT get its
// <pnplacehold>/<snplacehold> tokens rewritten on disk here. See
// PacketDependencies.ApplyPlayerPlaceholders -- that table's substitution
// happens in memory at dict-load time instead, specifically so switching to
// a different character mid-session (no app restart) re-substitutes cleanly
// instead of finding the token already consumed by whichever character
// activated first. story_so_far/dialog/bad_strings don't have that problem
// because they're always rebuilt wholesale from their *_template source
// (which never loses its tokens), not mutated in place.
internal static class PlayerDataMaterializer
{
    public static void Materialize(
        PacketDependencies deps,
        string jaPlayerName,
        string jaSiblingName,
        string enPlayerName,
        string enSiblingName,
        SiblingRelationship? relationship)
    {
        var db = deps.Db;

        var storyRows = db.ReadTemplateRows("story_so_far_template")
            .Select(row => (
                Ja: ReplaceWithJaNames(row.Ja, jaPlayerName, jaSiblingName, relationship),
                En: ReplaceWithEnNames(row.En, enPlayerName, enSiblingName, relationship)))
            .ToList();
        db.ReplaceStorySoFar(storyRows);

        var dialogRows = db.ReadFixedDialogTemplate()
            .Select(row => (
                Ja: ReplaceWithJaNames(row.Ja, jaPlayerName, jaSiblingName, relationship),
                En: ReplaceWithEnNames(row.En, enPlayerName, enSiblingName, relationship),
                row.BadString))
            .ToList();
        db.ReplaceFixedDialog(dialogRows);

        db.WritePlayerRecord(jaPlayerName, jaSiblingName, RelationshipKey(relationship));

        // PlayerContext sets its Ja/En name properties right after this call
        // returns (see PlayerContext.TryActivate), which is what
        // ApplyPlayerPlaceholders reads from -- dropping the m00 cache now
        // means the next M00Dict/NpcNameDict call rebuilds against those new
        // values instead of the previous character's (or an empty/no-op
        // substitution if this is the first character resolved this session).
        deps.InvalidateM00Cache();
    }

    // <pnplacehold>/<snplacehold> are unconditional; <kyodai_rel1-3> only
    // resolve when the relationship itself resolved (see SiblingRelationship),
    // otherwise those three tokens are left in place untouched -- same
    // graceful-miss behavior main has for an unrecognized relationship byte.
    private static string ReplaceWithEnNames(
        string text, string enPlayerName, string enSiblingName, SiblingRelationship? relationship)
    {
        var result = text
            .Replace("<pnplacehold>", enPlayerName)
            .Replace("<snplacehold>", enSiblingName);

        var word = RelationshipWordEn(relationship);
        if (word != null)
        {
            result = result
                .Replace("<kyodai_rel1>", word)
                .Replace("<kyodai_rel2>", word)
                .Replace("<kyodai_rel3>", word);
        }

        return result;
    }

    private static string ReplaceWithJaNames(
        string text, string jaPlayerName, string jaSiblingName, SiblingRelationship? relationship)
    {
        var result = text
            .Replace("<pnplacehold>", jaPlayerName)
            .Replace("<snplacehold>", jaSiblingName);

        var words = RelationshipWordsJa(relationship);
        if (words is { } w)
        {
            result = result
                .Replace("<kyodai_rel1>", w.Rel1)
                .Replace("<kyodai_rel2>", w.Rel2)
                .Replace("<kyodai_rel3>", w.Rel3);
        }

        return result;
    }

    private static string? RelationshipWordEn(SiblingRelationship? relationship) => relationship switch
    {
        SiblingRelationship.OlderBrother or SiblingRelationship.YoungerBrother => "brother",
        SiblingRelationship.OlderSister or SiblingRelationship.YoungerSister => "sister",
        _ => null,
    };

    // main uses three slightly different Japanese words per relationship
    // (varying politeness/register across kyodai_rel1/2/3) rather than one
    // word repeated three times the way the English side does.
    private static (string Rel1, string Rel2, string Rel3)? RelationshipWordsJa(SiblingRelationship? relationship) =>
        relationship switch
        {
            SiblingRelationship.OlderBrother => ("兄ちゃん", "お兄ちゃん", "兄"),
            SiblingRelationship.YoungerBrother => ("弟", "弟", "弟"),
            SiblingRelationship.OlderSister => ("姉ちゃん", "お姉ちゃん", "姉"),
            SiblingRelationship.YoungerSister => ("妹", "妹", "妹"),
            _ => null,
        };

    private static string RelationshipKey(SiblingRelationship? relationship) => relationship switch
    {
        SiblingRelationship.OlderBrother => "older_brother",
        SiblingRelationship.YoungerBrother => "younger_brother",
        SiblingRelationship.OlderSister => "older_sister",
        SiblingRelationship.YoungerSister => "younger_sister",
        _ => "",
    };
}
