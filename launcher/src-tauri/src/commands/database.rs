use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

use crate::commands::process::{exe_dir, find_app_dir};

#[derive(Serialize)]
pub struct DbRow {
    pub rowid: i64,
    pub values: Vec<Option<String>>,
}

#[derive(Serialize)]
pub struct DbTableData {
    pub columns: Vec<String>,
    pub rows: Vec<DbRow>,
}

fn db_path() -> Result<std::path::PathBuf, String> {
    let dir = exe_dir()?;
    Ok(find_app_dir(&dir).join("misc_files").join("clarity_dialog.db"))
}

/// Table/column identifiers cannot be parameterized in SQL, so validate them
/// before interpolating into query strings.
fn validate_identifier(name: &str) -> Result<(), String> {
    if name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Ok(())
    } else {
        Err(format!("Invalid identifier: {name}"))
    }
}

/// Return all user-defined table names in the database, sorted alphabetically.
#[tauri::command]
pub fn read_db_tables() -> Result<Vec<String>, String> {
    let path = db_path()?;
    if !path.exists() {
        return Err("misc_files/clarity_dialog.db not found".into());
    }

    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master \
             WHERE type='table' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name",
        )
        .map_err(|e| e.to_string())?;

    let tables = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    Ok(tables)
}

/// Return all columns and rows (with rowids) for the given table.
#[tauri::command]
pub fn read_db_table(table: String) -> Result<DbTableData, String> {
    validate_identifier(&table)?;
    let path = db_path()?;

    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(&format!("SELECT rowid, * FROM \"{table}\""))
        .map_err(|e| e.to_string())?;

    let col_count = stmt.column_count();
    let columns: Vec<String> = (1..col_count)
        .map(|i| stmt.column_name(i).unwrap_or("").to_string())
        .collect();

    let rows = stmt
        .query_map([], |row| {
            let rowid: i64 = row.get(0)?;
            let mut values = Vec::new();
            for i in 1..col_count {
                use rusqlite::types::Value;
                let cell: Result<Value, _> = row.get(i);
                let s = match cell {
                    Ok(Value::Null)       => None,
                    Ok(Value::Integer(n)) => Some(n.to_string()),
                    Ok(Value::Real(f))    => Some(f.to_string()),
                    Ok(Value::Text(s))    => Some(s),
                    Ok(Value::Blob(_))    => Some("[blob]".into()),
                    Err(_)                => None,
                };
                values.push(s);
            }
            Ok(DbRow { rowid, values })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    Ok(DbTableData { columns, rows })
}

/// Delete all rows from the dialog table (translation cache purge).
#[tauri::command]
pub fn purge_dialog_cache() -> Result<(), String> {
    let path = db_path()?;
    if !path.exists() {
        return Err("misc_files/clarity_dialog.db not found".into());
    }
    let conn = Connection::open(&path).map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM dialog", []).map_err(|e| e.to_string())?;
    Ok(())
}

/// Delete rows by rowid from the given table and persist to disk.
#[tauri::command]
pub fn delete_db_rows(table: String, rowids: Vec<i64>) -> Result<(), String> {
    if rowids.is_empty() {
        return Ok(());
    }
    validate_identifier(&table)?;
    let path = db_path()?;

    let conn = Connection::open(&path).map_err(|e| e.to_string())?;

    let placeholders = rowids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!("DELETE FROM \"{table}\" WHERE rowid IN ({placeholders})");

    conn.execute(&sql, rusqlite::params_from_iter(rowids.iter()))
        .map_err(|e| e.to_string())?;

    Ok(())
}
