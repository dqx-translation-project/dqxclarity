use futures_util::StreamExt;
use reqwest::Client;
use std::fs;
use std::path::Path;
use tauri::Emitter;

/// Returns true if DQXGame.exe is currently running.
fn is_dqx_running() -> bool {
    let mut cmd = std::process::Command::new("tasklist");
    cmd.args(["/FI", "IMAGENAME eq DQXGame.exe", "/NH", "/FO", "CSV"]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    match cmd.output() {
        Ok(out) => {
            let target = b"DQXGame.exe";
            out.stdout.windows(target.len()).any(|w| w.eq_ignore_ascii_case(target))
        }
        Err(_) => false,
    }
}

/// Returns true if the process is running with administrator privileges.
#[cfg(windows)]
fn is_admin() -> bool {
    #[link(name = "Shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
    }
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(windows))]
fn is_admin() -> bool { true }

fn http_client() -> Result<Client, String> {
    Client::builder()
        .user_agent("dqxclarity-launcher")
        .build()
        .map_err(|e| e.to_string())
}

/// Return the `browser_download_url` for the named asset in the latest release.
async fn latest_release_url(
    client: &Client,
    repo: &str,
    asset_name: &str,
) -> Result<String, String> {
    let api_url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let resp = client
        .get(&api_url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API error: HTTP {}", resp.status()));
    }

    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;

    json["assets"]
        .as_array()
        .and_then(|assets| {
            assets
                .iter()
                .find(|a| a["name"].as_str() == Some(asset_name))
        })
        .and_then(|a| a["browser_download_url"].as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Asset '{asset_name}' not found in the latest release of {repo}"))
}

/// Download `url`, streaming the body and emitting `patch-progress` events so
/// the frontend can drive a progress bar.
async fn fetch_with_progress(
    client: &Client,
    url: &str,
    app: &tauri::AppHandle,
) -> Result<Vec<u8>, String> {
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Download failed: HTTP {}", resp.status()));
    }

    let total = resp.content_length().unwrap_or(0);
    let mut downloaded: u64 = 0;
    let mut data: Vec<u8> = Vec::with_capacity(total as usize);
    let mut stream = resp.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| e.to_string())?;
        downloaded += chunk.len() as u64;
        data.extend_from_slice(&chunk);
        let _ = app.emit(
            "patch-progress",
            serde_json::json!({ "downloaded": downloaded, "total": total }),
        );
    }

    Ok(data)
}

fn write_exe(dest: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(dest, bytes).map_err(|e| format!("Failed to write {}: {e}", dest.display()))
}

/// Download the latest DQXLauncher.exe and overwrite Boot/DQXLauncher.exe.
#[tauri::command]
pub async fn patch_launcher(install_dir: String, app: tauri::AppHandle) -> Result<(), String> {
    let client = http_client()?;
    let url = latest_release_url(&client, "dqx-translation-project/dqx_en_launcher", "DQXLauncher.exe").await?;
    let bytes = fetch_with_progress(&client, &url, &app).await?;
    write_exe(&Path::new(&install_dir).join("Boot").join("DQXLauncher.exe"), &bytes)
}

/// Download the latest DQXConfig.exe and overwrite Game/DQXConfig.exe.
#[tauri::command]
pub async fn patch_config(install_dir: String, app: tauri::AppHandle) -> Result<(), String> {
    let client = http_client()?;
    let url = latest_release_url(&client, "dqx-translation-project/dqx_en_config", "DQXConfig.exe").await?;
    let bytes = fetch_with_progress(&client, &url, &app).await?;
    write_exe(&Path::new(&install_dir).join("Game").join("DQXConfig.exe"), &bytes)
}

/// Restore the original Japanese DQXLauncher.exe from the main branch of
/// the dqx_en_launcher repo.
#[tauri::command]
pub async fn restore_launcher(install_dir: String, app: tauri::AppHandle) -> Result<(), String> {
    let client = http_client()?;
    let bytes = fetch_with_progress(
        &client,
        "https://github.com/dqx-translation-project/dqx_en_launcher/raw/refs/heads/main/assets/DQXLauncher.exe",
        &app,
    ).await?;
    write_exe(&Path::new(&install_dir).join("Boot").join("DQXLauncher.exe"), &bytes)
}

/// Restore the original Japanese DQXConfig.exe from the main branch of
/// the dqx_en_config repo.
#[tauri::command]
pub async fn restore_config(install_dir: String, app: tauri::AppHandle) -> Result<(), String> {
    let client = http_client()?;
    let bytes = fetch_with_progress(
        &client,
        "https://github.com/dqx-translation-project/dqx_en_config/raw/refs/heads/main/assets/DQXConfig.exe",
        &app,
    ).await?;
    write_exe(&Path::new(&install_dir).join("Game").join("DQXConfig.exe"), &bytes)
}

/// Download the latest dat1 and idx translation mod files and write them to
/// the game's Content/Data directory. Requires admin privileges and DQX to
/// not be running.
#[tauri::command]
pub async fn patch_game_files(install_dir: String, app: tauri::AppHandle) -> Result<(), String> {
    if !is_admin() {
        return Err(
            "dqxclarity must be running as an administrator to apply game files. \
             Please re-launch as an administrator and try again."
                .into(),
        );
    }
    if is_dqx_running() {
        return Err("Please close DQX before patching game files.".into());
    }

    let data_dir = Path::new(&install_dir)
        .join("Game")
        .join("Content")
        .join("Data");
    let client = http_client()?;

    let dat1 = fetch_with_progress(
        &client,
        "https://github.com/dqx-translation-project/dqxclarity/releases/latest/download/data00000000.win32.dat1",
        &app,
    ).await?;
    fs::write(data_dir.join("data00000000.win32.dat1"), &dat1)
        .map_err(|e| format!("Failed to write dat1: {e}"))?;

    let idx = fetch_with_progress(
        &client,
        "https://github.com/dqx-translation-project/dqxclarity/releases/latest/download/data00000000.win32.idx",
        &app,
    ).await?;
    fs::write(data_dir.join("data00000000.win32.idx"), &idx)
        .map_err(|e| format!("Failed to write idx: {e}"))?;

    Ok(())
}
