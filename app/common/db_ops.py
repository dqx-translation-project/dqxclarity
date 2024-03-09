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


def sql_read(text: str, table: str) -> str:
    """Reads text from a SQLite table.

    :param text: Text to query against the database.
    :param table: Table to query against.
    :returns: Either a string of the found result or None if no match.
    """
    try:
        conn, cursor = init_db()
        escaped_text = text.replace("'", "''")
        selectQuery = f"SELECT en FROM {table} WHERE ja = '{escaped_text}'"
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
