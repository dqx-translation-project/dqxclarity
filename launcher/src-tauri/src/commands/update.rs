use crate::commands::process::{exe_dir, find_app_dir};
use reqwest::Client;
use serde::Serialize;
use std::fs;

#[derive(Serialize)]
pub struct UpdateInfo {
    pub version: String,
    pub body: String,
}

fn http_client() -> Result<Client, String> {
    Client::builder()
        .user_agent("dqxclarity-launcher")
        .build()
        .map_err(|e| e.to_string())
}

#[cfg(windows)]
fn system_python() -> Result<std::path::PathBuf, String> {
    use winreg::enums::*;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey(r"SOFTWARE\WOW6432Node\Python\PythonCore\3.11-32\InstallPath")
        .map_err(|_| "Python 3.11 (32-bit) not found in registry.".to_string())?;
    let path: String = key
        .get_value("ExecutablePath")
        .map_err(|e| format!("Could not read Python executable path: {e}"))?;
    Ok(std::path::PathBuf::from(path))
}

#[cfg(not(windows))]
fn system_python() -> Result<std::path::PathBuf, String> {
    Ok(std::path::PathBuf::from("python3"))
}

/// Check GitHub for a newer dqxclarity release. Returns version + release notes
/// if an update is available, or null if already up to date or check fails.
#[tauri::command]
pub async fn check_for_updates() -> Result<Option<UpdateInfo>, String> {
    let dir = exe_dir()?;
    let app_dir = find_app_dir(&dir);

    let version_path = app_dir.join("version.update");
    if !version_path.exists() {
        return Ok(None);
    }
    let cur_ver = fs::read_to_string(&version_path)
        .map_err(|e| e.to_string())?
        .trim()
        .to_string();

    let client = http_client()?;
    let resp = client
        .get("https://api.github.com/repos/dqx-translation-project/dqxclarity/releases/latest")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let tag = json["tag_name"].as_str().unwrap_or("").to_string();
    let new_ver = tag.trim_start_matches('v').to_string();
    let body = json["body"].as_str().unwrap_or("").to_string();

    if new_ver.is_empty() || new_ver == cur_ver {
        return Ok(None);
    }

    Ok(Some(UpdateInfo { version: tag, body }))
}

/// Download updater.py from the given release tag, spawn it with system
/// Python, then exit the launcher so the updater can replace files freely.
#[tauri::command]
pub async fn run_updater(tag: String, app: tauri::AppHandle) -> Result<(), String> {
    let dir = exe_dir()?;
    let app_dir = find_app_dir(&dir);

    let url = format!(
        "https://raw.githubusercontent.com/dqx-translation-project/dqxclarity/refs/tags/{tag}/app/updater.py"
    );

    let client = http_client()?;
    let bytes = client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .bytes()
        .await
        .map_err(|e| e.to_string())?;

    let updater_path = app_dir.join("updater.py");
    fs::write(&updater_path, &bytes).map_err(|e| e.to_string())?;

    let python = system_python()?;
    let mut cmd = std::process::Command::new(&python);
    cmd.arg(&updater_path).current_dir(&app_dir);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    cmd.spawn()
        .map_err(|e| format!("Failed to spawn updater: {e}"))?;

    app.exit(0);
    Ok(())
}
