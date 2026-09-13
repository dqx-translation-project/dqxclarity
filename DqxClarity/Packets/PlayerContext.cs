namespace DqxClarity.Packets;

// The four sibling relationships the game encodes as a single byte inside
// CharacterLogListPacket -- confirmed against real captures with known
// relationships (older_brother via an "Aiueoo"/"iiiiii" pair, younger_brother
// via Shobu/Katta, older_sister via Ellistan/Colette, younger_sister via
// New York/Rochester). Matches main branch's own byte encoding exactly
// (_determine_sibling_relationship in player.py), even though nothing here
// ever reads that byte out of process memory -- it's read straight off the
// wire instead. See CharacterLogListPacket's doc comment for the byte offset.
public enum SiblingRelationship
{
    OlderBrother,
    YoungerBrother,
    OlderSister,
    YoungerSister,
}

// One roster slot as reported by CharacterLogListPacket: a character on the
// account, their sibling, and the relationship byte between them. CharacterId
// is the persistent, high-entropy u32 confirmed to also show up in
// EntityPacket for a Player-kind entity representing that same character --
// see PlayerContext, which is what actually uses that correlation.
public sealed record CharacterRosterEntry(
    uint CharacterId,
    string JaPlayerName,
    string JaSiblingName,
    byte RelationshipByte)
{
    public SiblingRelationship? Relationship => RelationshipByte switch
    {
        1 => SiblingRelationship.OlderBrother,
        2 => SiblingRelationship.YoungerBrother,
        3 => SiblingRelationship.OlderSister,
        4 => SiblingRelationship.YoungerSister,
        _ => null,
    };
}

// The account's up-to-5-character roster, as last reported by
// CharacterLogListPacket. Keyed by CharacterId rather than name specifically
// so that two characters sharing the same player/sibling names (nothing
// stops that at character creation) still resolve unambiguously -- the id is
// an opaque, high-entropy value with no relation to the display name at all.
public sealed class PlayerRoster
{
    private readonly Dictionary<uint, CharacterRosterEntry> _entries = new();

    public void Update(IReadOnlyList<CharacterRosterEntry> entries)
    {
        _entries.Clear();
        foreach (var entry in entries)
            _entries[entry.CharacterId] = entry;
    }

    public bool TryGet(uint characterId, out CharacterRosterEntry entry)
    {
        if (_entries.TryGetValue(characterId, out var found))
        {
            entry = found;
            return true;
        }
        entry = null!;
        return false;
    }
}

// Hook-free replacement for main branch's player.py: identifies which
// character is currently logged in and resolves/materializes everything that
// used to come from a Frida login hook's init_player message.
//
// There's no login event on this branch's wire -- no packet fires once at
// login the way main's hook did. Instead this correlates two packets that
// already exist for unrelated reasons:
//   - CharacterLogListPacket (opened from the character log menu) reports up
//     to 5 (CharacterId, ja player name, ja sibling name, relationship byte)
//     tuples -- see PlayerRoster.
//   - EntityPacket, for any Player-kind entity, carries that same CharacterId
//     at a fixed offset. When it's YOUR character being described, the id
//     matches one of the roster entries above; when it's some other real
//     player nearby who also happens to be Player-kind, their id belongs to
//     a different account and simply won't be in your roster, so it's
//     silently ignored. This is why matching by id (not by name) matters --
//     it's immune to two of your own characters sharing a name, AND immune
//     to bystanders being mistaken for you.
//
// Whichever packet arrives first stores what it knows and asks the other
// side to retry: EntityPacket remembers "this id might be me" and tries an
// immediate match; CharacterLogListPacket, once the roster is known, asks
// PlayerContext to retry against whatever id was last seen. Either order
// converges to the same result.
//
// Once a match is found (or the active character changes -- e.g. logging
// into an alt mid-session), this resolves English names the normal way
// (local_player_names dict, romaji fallback), calls PlayerDataMaterializer to
// rebuild story_so_far/dialog/bad_strings from their *_template tables with
// <pnplacehold>/<snplacehold>/<kyodai_rel1-3> substituted in (same job as
// main's _load_story_so_far_into_db/_load_fixed_dialog_into_db), and drops
// the m00 dict cache so PacketDependencies.ApplyPlayerPlaceholders
// re-substitutes those same two tokens into m00_strings-backed dicts on next
// use (in memory, not on disk -- see that method's doc comment for why,
// namely so re-activating for a different character mid-session, without an
// app restart, substitutes cleanly instead of finding the token already
// consumed by whichever character activated first).
//
// Caveat this doesn't fully close: if the player never opens the character
// log screen in a given session, CharacterLogListPacket never fires, the
// roster stays empty, and none of this activates -- story_so_far/dialog
// lookups that depend on it keep missing and falling back to untranslated
// Japanese, same as before this existed. There's no substitute for that
// without a login hook; this only fires once something has actually
// triggered the roster packet.
public sealed class PlayerContext
{
    public uint? CharacterId { get; private set; }
    public string? JaPlayerName { get; private set; }
    public string? JaSiblingName { get; private set; }
    public string? EnPlayerName { get; private set; }
    public string? EnSiblingName { get; private set; }
    public SiblingRelationship? Relationship { get; private set; }

    private uint? _pendingEntityId;

    // Called by EntityPacket whenever it sees a Player-kind entity's id.
    public void NotifyEntityId(uint id, PacketDependencies deps)
    {
        if (CharacterId == id) return;
        _pendingEntityId = id;
        TryActivate(deps);
    }

    // Called by CharacterLogListPacket after it refreshes the roster, in case
    // an EntityPacket id was seen before the roster was known.
    public void NotifyRosterUpdated(PacketDependencies deps) => TryActivate(deps);

    private void TryActivate(PacketDependencies deps)
    {
        if (_pendingEntityId is not { } id) return;
        if (CharacterId == id) return;
        if (!deps.PlayerRoster.TryGet(id, out var entry)) return;

        // Work entirely off locals (not the nullable-annotated properties below)
        // so this stays non-null throughout without fighting the nullable
        // analyzer across the M00Dict/ResolveName calls in between.
        var jaPlayerName = entry.JaPlayerName;
        var jaSiblingName = entry.JaSiblingName;
        var relationship = entry.Relationship;

        var playerDict = deps.M00Dict("local_player_names");
        var enPlayerName = ResolveName(jaPlayerName, playerDict, deps);
        var enSiblingName = ResolveName(jaSiblingName, playerDict, deps);

        PlayerDataMaterializer.Materialize(
            deps, jaPlayerName, jaSiblingName, enPlayerName, enSiblingName, relationship);

        CharacterId = id;
        JaPlayerName = jaPlayerName;
        JaSiblingName = jaSiblingName;
        EnPlayerName = enPlayerName;
        EnSiblingName = enSiblingName;
        Relationship = relationship;
    }

    private static string ResolveName(string japanese, Dictionary<string, string> dict, PacketDependencies deps)
    {
        if (string.IsNullOrEmpty(japanese)) return japanese;
        if (dict.TryGetValue(japanese, out var known) && !string.IsNullOrEmpty(known)) return known;
        return deps.Romanizer.ToRomaji(japanese);
    }
}
