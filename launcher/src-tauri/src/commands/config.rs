use crate::commands::process::{exe_dir, find_app_dir};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn config_path() -> Result<std::path::PathBuf, String> {
    let dir = exe_dir()?;
    Ok(find_app_dir(&dir).join("user_settings.ini"))
}

/// Parse a simple INI file into section → (key → value).
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

fn to_bool(val: Option<&str>) -> bool {
    matches!(val, Some("True") | Some("true") | Some("1"))
}

fn bool_to_ini(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}

/// Update (or insert) a single key=value in the given section of an INI file,
/// preserving all other content verbatim.
fn update_ini_value(path: &Path, section: &str, key: &str, value: &str) -> Result<(), String> {
    let content = if path.exists() {
        fs::read_to_string(path).map_err(|e| e.to_string())?
    } else {
        String::new()
    };

    let mut out = String::new();
    let mut in_target = false;
    let mut key_written = false;
    let mut section_found = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_target && !key_written {
                // Key not seen before leaving the section — append it now
                write_kv(&mut out, key, value);
                key_written = true;
            }
            let sec = trimmed[1..trimmed.len() - 1].to_lowercase();
            in_target = sec == section;
            if in_target { section_found = true; }
            out.push_str(line);
            out.push('\n');
        } else if in_target {
            if let Some(idx) = trimmed.find('=') {
                let k = trimmed[..idx].trim().to_lowercase();
                if k == key {
                    write_kv(&mut out, key, value);
                    key_written = true;
                    continue;
                }
            }
            out.push_str(line);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }

    // End of file while still inside target section and key not yet written
    if in_target && !key_written {
        write_kv(&mut out, key, value);
    }

    // Section was never found — append it
    if !section_found {
        if !out.is_empty() {
            if !out.ends_with('\n') { out.push('\n'); }
            out.push('\n');
        }
        out.push_str(&format!("[{section}]\n"));
        write_kv(&mut out, key, value);
    }

    fs::write(path, out).map_err(|e| e.to_string())
}

fn write_kv(out: &mut String, key: &str, value: &str) {
    if value.is_empty() {
        out.push_str(&format!("{key} =\n"));
    } else {
        out.push_str(&format!("{key} = {value}\n"));
    }
}

/// Load config from user_settings.ini and return the shape the frontend expects.
#[tauri::command]
pub fn load_config() -> Result<Value, String> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(json!({ "launcher": {}, "translation": {}, "config": {} }));
    }

    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let sections = parse_ini(&content);
    let empty = HashMap::new();

    let l = sections.get("launcher").unwrap_or(&empty);
    let launcher = json!({
        "nameplates":          to_bool(l.get("nameplates").map(|s| s.as_str())),
        "update_game_files":   to_bool(l.get("updategamefiles").map(|s| s.as_str())),
        "disable_updates":     to_bool(l.get("disableupdates").map(|s| s.as_str())),
        "debug_logging":       to_bool(l.get("debuglogging").map(|s| s.as_str())),
        "community_logging":   to_bool(l.get("communitylogging").map(|s| s.as_str())),
        "simultaneous_launch": to_bool(l.get("simultaneouslaunch").map(|s| s.as_str())),
        "theme":               l.get("theme").cloned().unwrap_or_else(|| "rosie".to_string()),
    });

    let t = sections.get("translation").unwrap_or(&empty);
    let bool_keys = [
        "enabledeepltranslate",
        "enablegoogletranslate",
        "enablegoogletranslatefree",
        "enablecommunityapi",
    ];
    let mut trans_map = serde_json::Map::new();
    for (k, v) in t {
        if bool_keys.contains(&k.as_str()) {
            trans_map.insert(k.clone(), json!(to_bool(Some(v.as_str()))));
        } else {
            trans_map.insert(k.clone(), json!(v));
        }
    }

    let c = sections.get("config").unwrap_or(&empty);
    let config_section = json!({
        "installdirectory": c.get("installdirectory").cloned().unwrap_or_default(),
    });

    Ok(json!({
        "launcher":    launcher,
        "translation": Value::Object(trans_map),
        "config":      config_section,
    }))
}

/// Save launcher and translation settings back to user_settings.ini.
/// The [config] section is preserved from the existing file.
#[tauri::command]
pub fn save_config(launcher: Value, translation: Value) -> Result<(), String> {
    let path = config_path()?;

    // Parse the existing file once to preserve [config] keys and the theme.
    let (config_pairs, saved_theme): (Vec<(String, String)>, String) = if path.exists() {
        let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let sections = parse_ini(&content);
        let mut pairs: Vec<(String, String)> = sections
            .get("config")
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let theme = sections
            .get("launcher")
            .and_then(|l| l.get("theme"))
            .cloned()
            .unwrap_or_else(|| "rosie".to_string());
        (pairs, theme)
    } else {
        (Vec::new(), "default".to_string())
    };

    let mut out = String::new();

    // [translation]
    out.push_str("[translation]\n");
    let trans_keys: &[(&str, bool)] = &[
        ("enabledeepltranslate",      true),
        ("deepltranslatekey",         false),
        ("enablegoogletranslate",     true),
        ("googletranslatekey",        false),
        ("enablegoogletranslatefree", true),
        ("enablecommunityapi",        true),
        ("communityapikey",           false),
    ];
    if let Some(t) = translation.as_object() {
        for (key, is_bool) in trans_keys {
            let val_str = match t.get(*key) {
                Some(val) if *is_bool => bool_to_ini(val.as_bool().unwrap_or(false)).to_string(),
                Some(val)             => val.as_str().unwrap_or("").to_string(),
                None if *is_bool      => "False".to_string(),
                None                  => String::new(),
            };
            write_kv(&mut out, key, &val_str);
        }
    }
    out.push('\n');

    // [config] — only written if the section existed in the file
    if !config_pairs.is_empty() {
        out.push_str("[config]\n");
        for (k, v) in &config_pairs {
            write_kv(&mut out, k, v);
        }
        out.push('\n');
    }

    // [launcher]
    out.push_str("[launcher]\n");
    let launcher_keys: &[(&str, &str)] = &[
        ("communitylogging",   "community_logging"),
        ("nameplates",         "nameplates"),
        ("updategamefiles",    "update_game_files"),
        ("disableupdates",     "disable_updates"),
        ("debuglogging",       "debug_logging"),
        ("simultaneouslaunch", "simultaneous_launch"),
    ];
    if let Some(l) = launcher.as_object() {
        for (ini_key, json_key) in launcher_keys {
            let b = l.get(*json_key).and_then(|v| v.as_bool()).unwrap_or(false);
            out.push_str(&format!("{ini_key} = {}\n", bool_to_ini(b)));
        }
        // theme is a string — prefer what the frontend sends, fall back to saved value
        let theme = l.get("theme").and_then(|v| v.as_str()).unwrap_or(&saved_theme);
        write_kv(&mut out, "theme", theme);
    }

    fs::write(&path, out).map_err(|e| e.to_string())
}

/// Check that the given directory contains the expected DQX game data file.
/// Returns Ok(()) if valid, Err with a message if not.
#[tauri::command]
pub fn validate_dqx_dir(dir: String) -> Result<(), String> {
    let idx = Path::new(&dir)
        .join("Game")
        .join("Content")
        .join("Data")
        .join("data00000000.win32.idx");
    if idx.exists() {
        Ok(())
    } else {
        Err("Could not find Game/Content/Data/data00000000.win32.idx in the selected folder. Make sure you selected the top-level DQX installation folder.".into())
    }
}

/// Persist the DQX installation directory to user_settings.ini [config] section.
#[tauri::command]
pub fn save_game_dir(dir: String) -> Result<(), String> {
    let path = config_path()?;
    // Normalise to forward slashes to match the existing INI convention
    let dir = dir.replace('\\', "/");
    update_ini_value(&path, "config", "installdirectory", &dir)
}

/// Launch DQXBoot.exe from the given installation directory.
#[tauri::command]
pub fn launch_dqx(install_dir: String) -> Result<(), String> {
    let exe = Path::new(&install_dir).join("Boot").join("DQXBoot.exe");
    if !exe.exists() {
        return Err(format!("DQXBoot.exe not found at {}", exe.display()));
    }
    std::process::Command::new(&exe)
        .current_dir(Path::new(&install_dir).join("Boot"))
        .spawn()
        .map_err(|e| format!("Failed to launch DQXBoot.exe: {e}"))?;
    Ok(())
}

/// Launch DQXConfig.exe from the given installation directory.
#[tauri::command]
pub fn launch_dqx_config(install_dir: String) -> Result<(), String> {
    let exe = Path::new(&install_dir).join("Game").join("DQXConfig.exe");
    if !exe.exists() {
        return Err(format!("DQXConfig.exe not found at {}", exe.display()));
    }
    std::process::Command::new(&exe)
        .current_dir(Path::new(&install_dir).join("Game"))
        .spawn()
        .map_err(|e| format!("Failed to launch DQXConfig.exe: {e}"))?;
    Ok(())
}

/// Persist the chosen theme name to [launcher] in user_settings.ini.
#[tauri::command]
pub fn save_theme(theme: String) -> Result<(), String> {
    let path = config_path()?;
    update_ini_value(&path, "launcher", "theme", &theme)
}

/// No-op: INI is now the primary config format, migration is not needed.
#[tauri::command]
pub fn migrate_ini() -> Result<bool, String> {
    Ok(false)
}
