from common.lib import get_project_root
from loguru import logger as log

import sqlite3


def init_db() -> object:
    """Returns a tuple of db (connection, cursor) to be used to execute queries
    against."""
    db_file = get_project_root("misc_files/clarity_dialog.db")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    return (conn, cursor)


def ensure_db_structure():
    conn, cursor = init_db()
    query = """
    BEGIN TRANSACTION;
    CREATE TABLE IF NOT EXISTS "dialog" ("ja" TEXT NOT NULL UNIQUE,"npc_name" TEXT,"en" TEXT,"bg" TEXT,"cs" TEXT,"da" TEXT,"de" TEXT,"el" TEXT,"es" TEXT,"et" TEXT,"fi" TEXT,"fr" TEXT,"hu" TEXT,"it" TEXT,"lt" TEXT,"lv" TEXT,"nl" TEXT,"pl" TEXT,"pt" TEXT,"ro" TEXT,"ru" TEXT,"sk" TEXT,"sl" TEXT,"sv" TEXT,"zh" TEXT,PRIMARY KEY("ja"));
    CREATE TABLE IF NOT EXISTS "player" ("type" TEXT NOT NULL,"name" TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS "quests" ("ja" TEXT NOT NULL UNIQUE,"en" TEXT,"bg" TEXT,"cs" TEXT,"da" TEXT,"de" TEXT,"el" TEXT,"es" TEXT,"et" TEXT,"fi" TEXT,"fr" TEXT,"hu" TEXT,"it" TEXT,"lt" TEXT,"lv" TEXT,"nl" TEXT,"pl" TEXT,"pt" TEXT,"ro" TEXT,"ru" TEXT,"sk" TEXT,"sl" TEXT,"sv" TEXT,"zh" TEXT,PRIMARY KEY("ja"));
    CREATE TABLE IF NOT EXISTS "story_so_far" ("ja" TEXT NOT NULL UNIQUE,"en" TEXT,"bg" TEXT,"cs" TEXT,"da" TEXT,"de" TEXT,"el" TEXT,"es" TEXT,"et" TEXT,"fi" TEXT,"fr" TEXT,"hu" TEXT,"it" TEXT,"lt" TEXT,"lv" TEXT,"nl" TEXT,"pl" TEXT,"pt" TEXT,"ro" TEXT,"ru" TEXT,"sk" TEXT,"sl" TEXT,"sv" TEXT,"zh" TEXT);
    CREATE TABLE IF NOT EXISTS "walkthrough" ("ja" TEXT NOT NULL UNIQUE,"en" TEXT,"bg" TEXT,"cs" TEXT,"da" TEXT,"de" TEXT,"el" TEXT,"es" TEXT,"et" TEXT,"fi" TEXT,"fr" TEXT,"hu" TEXT,"it" TEXT,"lt" TEXT,"lv" TEXT,"nl" TEXT,"pl" TEXT,"pt" TEXT,"ro" TEXT,"ru" TEXT,"sk" TEXT,"sl" TEXT,"sv" TEXT,"zh" TEXT,PRIMARY KEY("ja"));
    CREATE UNIQUE INDEX IF NOT EXISTS "dialog_index" ON "dialog" ("ja");
    CREATE UNIQUE INDEX IF NOT EXISTS "quests_index" ON "quests" ("ja");
    CREATE UNIQUE INDEX IF NOT EXISTS "story_so_far_index" ON "story_so_far" ("ja");
    CREATE UNIQUE INDEX IF NOT EXISTS "walkthrough_index" ON "walkthrough" ("ja");
    END TRANSACTION;
    """
    cursor.executescript(query)
    conn.commit()
    conn.close()


def sql_read(text: str, table: str, language: str) -> str:
    """Reads text from a SQLite table.

    :param text: Text to query against the database.
    :param table: Table to query against.
    :param language: Language to query against.
    :returns: Either a string of the found result or None if no match.
    """
    try:
        conn, cursor = init_db()
        escaped_text = text.replace("'", "''")
        selectQuery = f"SELECT {language} FROM {table} WHERE ja = '{escaped_text}'"
        cursor.execute(selectQuery)
        results = cursor.fetchone()

        if results is not None:
            return results[0].replace("''", "'")
        else:
            return None
    except sqlite3.Error:
        log.exception(f"Failed to query {table}.")
    finally:
        if conn:
            conn.close()


def sql_write(source_text, translated_text, table, language):
    """Writes or updates text to a SQLite table.

    :param source_text: Text to search against the table.
    :param translated_text: Translated text to insert/update into the
        database.
    :param table: Table to insert the text into.
    :param language: The applicable language to insert the text into.
    :returns: This function returns nothing; it only writes/updates to
        the database.
    """
    try:
        conn, cursor = init_db()
        escaped_text = translated_text.replace("'", "''")
        select_query = f"SELECT ja FROM {table} WHERE ja = '{source_text}'"
        update_query = f"UPDATE {table} SET {language} = '{escaped_text}' WHERE ja = '{source_text}'"
        insert_query = f"INSERT INTO {table} (ja, {language}) VALUES ('{source_text}', '{escaped_text}')"
        results = cursor.execute(select_query)

        if results.fetchone() is None:
            cursor.execute(insert_query)
        else:
            cursor.execute(update_query)

        conn.commit()
    except sqlite3.Error as e:
        log.exception(f"Unable to write data to {table}.")
    finally:
        if conn:
            conn.close()
