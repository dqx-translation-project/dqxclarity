"""Hooks player login to initialize database with player/sibling data.

This hook is triggered once the player has logged into the game with their
selected character.

It currently reads:
    - The player's name
    - The sibling's name
    - The relationship between player and sibling
It uses this information to update various data in the local database that replaces placeholder tags
related to the above read data. This makes it so that when the strings are encountered in game, they
exactly match when being looked up in database, returning a result.
"""
from common.db_ops import db_query, generate_m00_dict, init_db
from common.translate import transliterate_player_name
from loguru import logger as log

_player_names = None


def _init_player_names():
    """Initialize the player names database if not already loaded."""
    global _player_names

    if _player_names is not None:
        return _player_names

    _player_names = generate_m00_dict(files="'local_player_names'")
    return _player_names


def _determine_sibling_relationship(relationship_byte: int) -> str:
    """Determine sibling relationship from byte value.

    :param relationship_byte: Byte value from memory (1-4)
    :returns: String describing relationship
    """
    if relationship_byte == 0x01:
        return "older_brother"
    elif relationship_byte == 0x02:
        return "younger_brother"
    elif relationship_byte == 0x03:
        return "older_sister"
    elif relationship_byte == 0x04:
        return "younger_sister"
    else:
        return "unknown"


def _get_en_player_name(name: str) -> str:
    """Get English player name from database or transliterate.

    :param name: Japanese player name
    :returns: English player name
    """
    player_names = _init_player_names()

    if result := player_names.get(name):
        return result

    return transliterate_player_name(word=name)


def _write_player(ja_player_name: str, ja_sibling_name: str, sibling_relationship: str):
    """Write player data to database.

    :param ja_player_name: Japanese player name
    :param ja_sibling_name: Japanese sibling name
    :param sibling_relationship: Sibling relationship string
    """
    query = f"""
    BEGIN TRANSACTION;
    DELETE FROM player;
    INSERT INTO player (type, name) VALUES
        ('player', '{ja_player_name}'),
        ('sibling', '{ja_sibling_name}'),
        ('sibling_relationship', '{sibling_relationship}');
    END TRANSACTION;
    """

    try:
        conn, cursor = init_db()
        cursor.executescript(query)
        conn.commit()
    finally:
        conn.close()


def _replace_with_en_names(string: str, en_player_name: str, en_sibling_name: str, sibling_relationship: str) -> str:
    """Replace placeholders with English names.

    :param string: String with placeholders
    :param en_player_name: English player name
    :param en_sibling_name: English sibling name
    :param sibling_relationship: Sibling relationship
    :returns: String with placeholders replaced
    """
    new_string = string.replace("<pnplacehold>", en_player_name)
    new_string = new_string.replace("<snplacehold>", en_sibling_name)

    if sibling_relationship in ["older_brother", "younger_brother"]:
        new_string = new_string.replace("<kyodai_rel1>", "brother")
        new_string = new_string.replace("<kyodai_rel2>", "brother")
        new_string = new_string.replace("<kyodai_rel3>", "brother")
    elif sibling_relationship in ["older_sister", "younger_sister"]:
        new_string = new_string.replace("<kyodai_rel1>", "sister")
        new_string = new_string.replace("<kyodai_rel2>", "sister")
        new_string = new_string.replace("<kyodai_rel3>", "sister")

    return new_string


def _replace_with_ja_names(string: str, ja_player_name: str, ja_sibling_name: str, sibling_relationship: str) -> str:
    """Replace placeholders with Japanese names.

    :param string: String with placeholders
    :param ja_player_name: Japanese player name
    :param ja_sibling_name: Japanese sibling name
    :param sibling_relationship: Sibling relationship
    :returns: String with placeholders replaced
    """
    new_string = string.replace("<pnplacehold>", ja_player_name)
    new_string = new_string.replace("<snplacehold>", ja_sibling_name)

    if sibling_relationship == "older_brother":
        new_string = new_string.replace("<kyodai_rel1>", "兄ちゃん")
        new_string = new_string.replace("<kyodai_rel2>", "お兄ちゃん")
        new_string = new_string.replace("<kyodai_rel3>", "兄")
    elif sibling_relationship == "younger_brother":
        new_string = new_string.replace("<kyodai_rel1>", "弟")
        new_string = new_string.replace("<kyodai_rel2>", "弟")
        new_string = new_string.replace("<kyodai_rel3>", "弟")
    elif sibling_relationship == "older_sister":
        new_string = new_string.replace("<kyodai_rel1>", "姉ちゃん")
        new_string = new_string.replace("<kyodai_rel2>", "お姉ちゃん")
        new_string = new_string.replace("<kyodai_rel3>", "姉")
    elif sibling_relationship == "younger_sister":
        new_string = new_string.replace("<kyodai_rel1>", "妹")
        new_string = new_string.replace("<kyodai_rel2>", "妹")
        new_string = new_string.replace("<kyodai_rel3>", "妹")

    return new_string


def _load_story_so_far_into_db(ja_player_name: str, ja_sibling_name: str, en_player_name: str, en_sibling_name: str, sibling_relationship: str):
    """Load story so far data into database with placeholder replacements.

    :param ja_player_name: Japanese player name
    :param ja_sibling_name: Japanese sibling name
    :param en_player_name: English player name
    :param en_sibling_name: English sibling name
    :param sibling_relationship: Sibling relationship
    """
    conn, cursor = init_db()

    query = "DELETE FROM story_so_far"
    cursor.execute(query)

    query = "SELECT * FROM story_so_far_template"
    cursor.execute(query)

    results = cursor.fetchall()

    query_list = []
    for ja, en in results:
        fixed_ja = _replace_with_ja_names(ja.replace("'", "''"), ja_player_name, ja_sibling_name, sibling_relationship)
        fixed_en = _replace_with_en_names(en.replace("'", "''"), en_player_name, en_sibling_name, sibling_relationship)

        query_value = f"('{fixed_ja}', '{fixed_en}')"
        query_list.append(query_value)

    insert_values = ','.join(query_list)
    query = f"INSERT INTO story_so_far (ja, en) VALUES {insert_values};"
    cursor.execute(query)
    conn.commit()
    conn.close()


def _load_fixed_dialog_into_db(ja_player_name: str, ja_sibling_name: str, en_player_name: str, en_sibling_name: str, sibling_relationship: str):
    """Load fixed dialog data into database with placeholder replacements.

    :param ja_player_name: Japanese player name
    :param ja_sibling_name: Japanese sibling name
    :param en_player_name: English player name
    :param en_sibling_name: English sibling name
    :param sibling_relationship: Sibling relationship
    """
    conn, cursor = init_db()

    query = "DELETE FROM bad_strings"
    cursor.execute(query)

    query = "SELECT ja, en, bad_string FROM fixed_dialog_template"
    cursor.execute(query)

    results = cursor.fetchall()

    dialog_list = []
    bad_strings_list = []
    for ja, en, bad_string in results:
        fixed_ja = _replace_with_ja_names(ja.replace("'", "''"), ja_player_name, ja_sibling_name, sibling_relationship)
        fixed_en = _replace_with_en_names(en.replace("'", "''"), en_player_name, en_sibling_name, sibling_relationship)

        query_value = f"('{fixed_ja}', '{fixed_en}')"

        if bad_string == 0:
            dialog_list.append(query_value)
        elif bad_string == 1:
            bad_strings_list.append(query_value)

    dialog_values = ','.join(dialog_list)
    bad_string_values = ','.join(bad_strings_list)

    if len(dialog_values) > 0:
        query = f"INSERT OR REPLACE INTO dialog (ja, en) VALUES {dialog_values};"
        cursor.execute(query)
    if len(bad_string_values) > 0:
        query = f"INSERT OR REPLACE INTO bad_strings (ja, en) VALUES {bad_string_values};"
        cursor.execute(query)
    conn.commit()
    conn.close()


def _update_m00_table(ja_player_name: str, ja_sibling_name: str, en_player_name: str, en_sibling_name: str):
    """Update m00 strings table with player/sibling name placeholders.

    :param ja_player_name: Japanese player name
    :param ja_sibling_name: Japanese sibling name
    :param en_player_name: English player name
    :param en_sibling_name: English sibling name
    """
    ja_query = f"""UPDATE m00_strings SET
        ja = replace(ja, '<pnplacehold>', '{ja_player_name}'),
        en = replace(en, '<pnplacehold>', '{en_player_name}')
    """
    en_query = f"""UPDATE m00_strings SET
        en = replace(en, '<snplacehold>', '{en_sibling_name}'),
        ja = replace(ja, '<snplacehold>', '{ja_sibling_name}')
    """

    db_query(ja_query)
    db_query(en_query)


def initialize_player_data(ja_player_name: str, ja_sibling_name: str, relationship_byte: int):
    """Initialize all player-related database data.

    :param ja_player_name: Japanese player name
    :param ja_sibling_name: Japanese sibling name
    :param relationship_byte: Byte value representing sibling
        relationship
    """
    try:
        # determine relationship
        sibling_relationship = _determine_sibling_relationship(relationship_byte)

        # get English names
        en_player_name = _get_en_player_name(ja_player_name)
        en_sibling_name = _get_en_player_name(ja_sibling_name)

        log.info("Initializing database:")
        log.info(f"  Player: {ja_player_name} -> {en_player_name}")
        log.info(f"  Sibling: {ja_sibling_name} -> {en_sibling_name} ({sibling_relationship})")

        # update all database tables
        _write_player(ja_player_name, ja_sibling_name, sibling_relationship)
        _load_story_so_far_into_db(ja_player_name, ja_sibling_name, en_player_name, en_sibling_name, sibling_relationship)
        _load_fixed_dialog_into_db(ja_player_name, ja_sibling_name, en_player_name, en_sibling_name, sibling_relationship)
        _update_m00_table(ja_player_name, ja_sibling_name, en_player_name, en_sibling_name)

        log.success("Database initialization complete")

    except Exception as e:
        log.exception(f"Initialization failed: {e}")


def on_message(message, data, script):
    """Message handler for player hook.

    Args:
        message: Message dict from Frida script
        data: Binary data (if any) from Frida script
        script: Frida script instance
    """
    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload.get('type', 'unknown')

        if msg_type == 'init_player':
            # frida script sent player data
            ja_player_name = payload.get('player_name', '')
            ja_sibling_name = payload.get('sibling_name', '')
            relationship_byte = payload.get('relationship_byte', 0)

            # process async
            initialize_player_data(ja_player_name, ja_sibling_name, relationship_byte)

        elif msg_type == 'info':
            log.debug(f"{payload['payload']}")
        elif msg_type == 'error':
            log.error(f"{payload['payload']}")
        else:
            log.debug(f"[player] {payload}")

    elif message['type'] == 'error':
        log.error(f"[JS ERROR] [player] {message.get('stack', message)}")
