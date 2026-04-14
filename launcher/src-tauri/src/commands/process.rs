use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;
use tauri::{Emitter, Manager, State};
use tokio::io::{AsyncBufReadExt, BufReader};

#[cfg(windows)]
fn no_window(cmd: &mut tokio::process::Command) {
    use std::os::windows::process::CommandExt;
    cmd.as_std_mut().creation_flags(0x08000000); // CREATE_NO_WINDOW
}
#[cfg(not(windows))]
fn no_window(_cmd: &mut tokio::process::Command) {}

/// Walk up from exe_dir until we find a directory containing main.py.
pub fn find_app_dir(exe_dir: &PathBuf) -> PathBuf {
    let mut dir = exe_dir.clone();
    for _ in 0..4 {
        if dir.join("main.py").exists() {
            return std::fs::canonicalize(&dir).unwrap_or(dir);
        }
        dir = dir.join("..");
    }
    // fallback: one level up
    let parent = exe_dir.join("..");
    std::fs::canonicalize(&parent).unwrap_or(parent)
}

#[derive(Clone, serde::Serialize)]
pub struct LogLine {
    pub level: String, // "info" | "error"
    pub line: String,
}

pub struct ProcessState {
    pub child_id: Mutex<Option<u32>>,
    pub user_stopped: Mutex<bool>,
}

pub fn exe_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    exe.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "Could not determine executable directory".to_string())
}

/// Read misc_files/name_overrides.json from the app directory.
/// Returns the file contents, or a "not found" message string on any failure.
#[tauri::command]
pub fn read_name_overrides() -> String {
    let Ok(dir) = exe_dir() else {
        return "misc_files/name_overrides.json not found".into();
    };
    let path = find_app_dir(&dir).join("misc_files").join("name_overrides.json");
    std::fs::read_to_string(path)
        .unwrap_or_else(|_| "misc_files/name_overrides.json not found".into())
}

/// Write content to misc_files/name_overrides.json, creating the directory if needed.
#[tauri::command]
pub fn save_name_overrides(content: String) -> Result<(), String> {
    let Ok(dir) = exe_dir() else {
        return Err("Cannot determine executable directory".into());
    };
    let path = find_app_dir(&dir).join("misc_files").join("name_overrides.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, content).map_err(|e| e.to_string())
}

/// Read the version string from version.update in the app directory.
/// Returns "???" if the file cannot be found, read, or parsed.
#[tauri::command]
pub fn get_version() -> String {
    let Ok(dir) = exe_dir() else { return "???".into() };
    let app_dir = find_app_dir(&dir);
    std::fs::read_to_string(app_dir.join("version.update"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "???".into())
}

/// Spawn the Python process and stream its output back as log-line events.
#[tauri::command]
pub async fn launch_clarity(
    app: tauri::AppHandle,
    state: State<'_, ProcessState>,
    args: Vec<String>,
) -> Result<(), String> {
    let dir = exe_dir()?;
    let python = dir.join("venv").join("Scripts").join("python.exe");

    if !python.exists() {
        return Err("Python executable not found in venv. Please run setup first.".to_string());
    }

    let app_dir = find_app_dir(&dir);

    let mut py_cmd = tokio::process::Command::new(&python);
    py_cmd
        .arg("-m")
        .arg("main")
        .args(&args)
        // Suppress cryptography warning expected on 32-bit Python
        .env("PYTHONWARNINGS", "ignore::UserWarning")
        .current_dir(&app_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    no_window(&mut py_cmd);
    let mut child = py_cmd
        .spawn()
        .map_err(|e| format!("Failed to launch dqxclarity: {e}"))?;

    // Store PID so stop_clarity can kill it
    if let Some(id) = child.id() {
        *state.child_id.lock().unwrap() = Some(id);
    }

    // Stream stdout
    if let Some(stdout) = child.stdout.take() {
        let mut lines = BufReader::new(stdout).lines();
        let app_clone = app.clone();
        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = app_clone.emit("log-line", LogLine { level: "info".into(), line });
            }
        });
    }

    // Stream stderr
    if let Some(stderr) = child.stderr.take() {
        let mut lines = BufReader::new(stderr).lines();
        let app_clone = app.clone();
        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = app_clone.emit("log-line", LogLine { level: "error".into(), line });
            }
        });
    }

    // Wait for process to exit and emit a final event (unless stop_clarity already did)
    let app_clone = app.clone();
    tokio::spawn(async move {
        let _ = child.wait().await;
        let process_state = app_clone.state::<ProcessState>();
        *process_state.child_id.lock().unwrap() = None;
        let was_user_stopped = {
            let mut flag = process_state.user_stopped.lock().unwrap();
            let val = *flag;
            *flag = false;
            val
        };
        if !was_user_stopped {
            let _ = app_clone.emit(
                "log-line",
                LogLine {
                    level: "info".into(),
                    line: "--- process exited ---".into(),
                },
            );
            let _ = app_clone.emit("process-exited", ());
        }
    });

    Ok(())
}

/// Kill the running Python process if one is active.
#[tauri::command]
pub fn stop_clarity(app: tauri::AppHandle, state: State<'_, ProcessState>) -> Result<(), String> {
    let pid = state.child_id.lock().unwrap().take();
    if let Some(id) = pid {
        *state.user_stopped.lock().unwrap() = true;

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &id.to_string(), "/T", "/F"])
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .output();
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &id.to_string()])
                .output();
        }

        // Emit immediately — don't wait for child.wait() to drain the pipes
        let _ = app.emit("process-exited", ());
    }
    Ok(())
}
