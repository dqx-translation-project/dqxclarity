use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

fn exe_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    exe.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "Could not determine executable directory".to_string())
}

fn config_path() -> Result<PathBuf, String> {
    Ok(exe_dir()?.join("user_settings.json"))
}

/// Load the full config from user_settings.json next to the exe.
/// Returns a default empty structure if the file does not exist yet.
#[tauri::command]
pub fn load_config() -> Result<Value, String> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(json!({ "launcher": {}, "translation": {} }));
    }
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&content).map_err(|e| e.to_string())
}

/// Save launcher and translation settings back to user_settings.json.
/// Other top-level keys in the file are preserved.
#[tauri::command]
pub fn save_config(launcher: Value, translation: Value) -> Result<(), String> {
    let path = config_path()?;

    // Read existing file so we preserve keys we don't own
    let mut full: Value = if path.exists() {
        let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        serde_json::from_str(&content).unwrap_or(json!({}))
    } else {
        json!({})
    };

    // Replace launcher section wholesale — Tauri owns this
    full["launcher"] = launcher;

    // Merge translation fields individually — Python may have keys we don't know about
    let existing_translation = full["translation"].as_object().cloned().unwrap_or_default();
    let mut merged = existing_translation;
    if let Some(map) = translation.as_object() {
        for (k, v) in map {
            merged.insert(k.clone(), v.clone());
        }
    }
    full["translation"] = Value::Object(merged);

    let content = serde_json::to_string_pretty(&full).map_err(|e| e.to_string())?;
    fs::write(&path, content).map_err(|e| e.to_string())
}

/// Parse a simple INI file into a map of section → (key → value).
/// Handles standard [section] / key=value format, no escaping needed for our use case.
fn parse_ini(content: &str) -> HashMap<String, HashMap<String, String>> {
    let mut result: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].to_lowercase();
        } else if let Some(idx) = line.find('=') {
            let key = line[..idx].trim().to_lowercase();
            let val = line[idx + 1..].trim().to_string();
            result.entry(current.clone()).or_default().insert(key, val);
        }
    }
    result
}

/// One-time migration from user_settings.ini to user_settings.json.
/// Returns true if migration was performed, false if nothing needed to be done.
#[tauri::command]
pub fn migrate_ini() -> Result<bool, String> {
    let dir = exe_dir()?;
    let ini_path = dir.join("user_settings.ini");
    let json_path = dir.join("user_settings.json");

    if !ini_path.exists() || json_path.exists() {
        return Ok(false);
    }

    let ini_content = fs::read_to_string(&ini_path).map_err(|e| e.to_string())?;
    let sections = parse_ini(&ini_content);

    fn to_bool(val: Option<&str>) -> bool {
        matches!(val, Some("True") | Some("true") | Some("1"))
    }

    let empty: HashMap<String, String> = HashMap::new();

    // Build launcher section
    let l = sections.get("launcher").unwrap_or(&empty);
    let launcher = json!({
        "nameplates":        to_bool(l.get("nameplates").map(|s| s.as_str())),
        "update_game_files": to_bool(l.get("updategamefiles").map(|s| s.as_str())),
        "disable_updates":   to_bool(l.get("disableupdates").map(|s| s.as_str())),
        "debug_logging":     to_bool(l.get("debuglogging").map(|s| s.as_str())),
        "community_logging": to_bool(l.get("communitylogging").map(|s| s.as_str()))
    });

    // Build translation section — preserve exact key names Python expects
    let bool_keys = [
        "enabledeepltranslate",
        "enablegoogletranslate",
        "enablecommunityapi",
        "enablegoogletranslatefree",
    ];
    let mut trans_map = serde_json::Map::new();
    if let Some(t) = sections.get("translation") {
        for (k, v) in t {
            if bool_keys.contains(&k.as_str()) {
                trans_map.insert(k.clone(), json!(to_bool(Some(v.as_str()))));
            } else {
                trans_map.insert(k.clone(), json!(v));
            }
        }
    }
    let translation = Value::Object(trans_map);

    let result = json!({ "launcher": launcher, "translation": translation });
    let content = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
    fs::write(&json_path, content).map_err(|e| e.to_string())?;
    Ok(true)
}
