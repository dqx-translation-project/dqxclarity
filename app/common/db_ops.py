from common.lib import get_project_root
from loguru import logger as log

import sqlite3


def init_db() -> object:
    """Returns a tuple of db (connection, cursor)."""
    db_file = get_project_root("misc_files/clarity_dialog.db")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    return (conn, cursor)


def create_db_schema():
    try:
        conn, cursor = init_db()
        schema_file = get_project_root('common/db_scripts/schema.sql')

        with open(schema_file) as f:
            script = f.read()

        cursor.executescript(script)
        conn.commit()
    except sqlite3.Error as e:
        log.exception(f"Failed to create schema. {e}.")
    finally:
        conn.close()


def fix_m00_tables_schema():
    """Drops the primary key (if exists) for the m00_strings table."""
    table = "m00_strings"

    try:
        conn, cursor = init_db()
        query = f'SELECT l.name FROM pragma_table_info("{table}") as l WHERE l.pk <> 0'
        cursor.execute(query)
        results = cursor.fetchall()
        for result in results:
            if result[0] == "ja":
                drop_m00_table = f"DROP TABLE IF EXISTS m00_strings"
                drop_m00_index = f"DROP INDEX IF EXISTS m00_strings.m00_strings_index"
                cursor.execute(drop_m00_table)
                cursor.execute(drop_m00_index)
        conn.commit()
    except sqlite3.Error as e:
        log.exception(f"Failed to drop existing column. {e}")
    finally:
        conn.close()


def db_query(query: str):
    """Executes a freeform query against the database.

    Does not return data.
    """
    try:
        conn, cursor = init_db()
        cursor.execute(query)
        conn.commit()
    except sqlite3.Error as e:
        log.exception(f"Query failed. {e}")
    finally:
        conn.close()


def generate_m00_dict(files: str = "") -> dict:
    """Queries the m00_strings table. Returns a dictionary of all results.

    :param files: Comma-delimited string of files to get from generate.
        Ensure you wrap each file in single quotes as this is a SQL
        query.
    :returns: Dict
    """
    try:
        data = {}
        conn, cursor = init_db()

        query = "SELECT * FROM m00_strings"

        if files:
            query += f" WHERE file IN ({files})"

        cursor.execute(query)
        results = cursor.fetchall()

        for ja, en, file in results:
            data[ja] = en

        return data

    except sqlite3.Error as e:
        log.exception(f"Query failed. {e}.")
    finally:
        if conn:
            conn.close()


def generate_glossary_dict() -> dict:
    """Queries the glossary table.

    Returns a dictionary of all results.
    """
    try:
        data = {}
        conn, cursor = init_db()

        query = "SELECT * FROM glossary"

        cursor.execute(query)
        results = cursor.fetchall()

        for ja, en in results:
            data[ja] = en

        return data

    except sqlite3.Error as e:
        log.exception(f"Query failed. {e}.")
    finally:
        if conn:
            conn.close()


def sql_read(text: str, table: str, wildcard: bool = False) -> str:
    """Reads text from a SQLite table.

    :param text: Text to query against the database.
    :param table: Table to query against.
    :param wildcard: Whether to use LIKE syntax instead of an exact
        match.
    :returns: Either a string of the first found result or None if no
        match.
    """
    try:
        conn, cursor = init_db()
        escaped_text = text.replace("'", "''")
        selectQuery = f"SELECT en FROM {table} WHERE ja = '{escaped_text}'"

        if wildcard:
            # because of newlines in our wildcard search, we replace \n with %.
            escaped_text = escaped_text.replace('\n', '%')
            selectQuery = f"SELECT en FROM {table} WHERE ja LIKE '%{escaped_text}%'"

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


def sql_write(source_text: str, translated_text: str, table: str):
    """Writes or updates text to a SQLite table.

    :param source_text: Text to search against the table.
    :param translated_text: Translated text to insert/update into the
        database.
    :param table: Table to insert the text into.
    :returns: This function returns nothing; it only writes/updates to
        the database.
    """
    try:
        conn, cursor = init_db()
        escaped_text = translated_text.replace("'", "''")
        select_query = f"SELECT ja FROM {table} WHERE ja = '{source_text}'"
        update_query = f"UPDATE {table} SET en = '{escaped_text}' WHERE ja = '{source_text}'"
        insert_query = f"INSERT INTO {table} (ja, en) VALUES ('{source_text}', '{escaped_text}')"
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


def search_bad_strings(text: str):
    """Searches every row in the bad_strings table for a match against the text
    arg.

    :param text: The string to compare the bad_string rows to.
    :returns: The english string it matched against or None if there is
        no match.
    """
    try:
        conn, cursor = init_db()

        query = "SELECT * FROM bad_strings"

        cursor.execute(query)
        results = cursor.fetchall()

        for ja, en in results:
            if ja in text:
                return en

        return None

    except sqlite3.Error as e:
        log.exception(f"Query failed. {e}.")
    finally:
        if conn:
            conn.close()
