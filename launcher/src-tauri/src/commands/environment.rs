use std::path::PathBuf;
use std::process::Stdio;
use tauri::Emitter;
use tokio::io::{AsyncBufReadExt, BufReader};

/// Suppress console window popups when spawning subprocesses on Windows.
#[cfg(windows)]
fn no_window(cmd: &mut tokio::process::Command) {
    use std::os::windows::process::CommandExt;
    cmd.as_std_mut().creation_flags(0x08000000); // CREATE_NO_WINDOW
}
#[cfg(not(windows))]
fn no_window(_cmd: &mut tokio::process::Command) {}

const PYTHON_VERSION: &str = "3.11.3";
const PYTHON_INSTALLER: &str = "python-3.11.3.exe";
const PYTHON_URL: &str = "https://www.python.org/ftp/python/3.11.3/python-3.11.3.exe";

// pragma: allowlist secret
const PYTHON_MD5: &str = "691232496E346CE0860AEF052DD6844F";

#[derive(Clone, serde::Serialize)]
pub struct SetupEvent {
    pub step: String,
    pub status: String, // "running" | "done" | "error" | "info"
    pub message: String,
}

fn exe_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    exe.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "Could not determine executable directory".to_string())
}

fn emit(app: &tauri::AppHandle, step: &str, status: &str, message: &str) {
    let _ = app.emit(
        "setup-step",
        SetupEvent {
            step: step.to_string(),
            status: status.to_string(),
            message: message.to_string(),
        },
    );
}

/// Check that the app is not running from a OneDrive-synced path.
fn check_path_safety(dir: &PathBuf) -> Result<(), String> {
    let path_str = dir.to_string_lossy().to_lowercase();
    if path_str.contains("onedrive") {
        return Err(
            "dqxclarity is running from a OneDrive folder. OneDrive sync interferes with the database. \
             Please move the application to a non-synced location and try again."
                .to_string(),
        );
    }
    Ok(())
}

/// Look up the Python 3.11-32 executable path from the Windows registry.
#[cfg(target_os = "windows")]
fn find_python_exe() -> Option<PathBuf> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey(r"SOFTWARE\WOW6432Node\Python\PythonCore\3.11-32\InstallPath")
        .ok()?;
    let exe_path: String = key.get_value("ExecutablePath").ok()?;
    let path = PathBuf::from(exe_path);
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

#[cfg(not(target_os = "windows"))]
fn find_python_exe() -> Option<PathBuf> {
    // On non-Windows, attempt to find python3.11 in PATH
    which::which("python3.11").ok()
}

/// Download the Python 3.11.3 32-bit installer, verify its MD5, and run it.
async fn download_and_install_python(app: &tauri::AppHandle, dir: &PathBuf) -> Result<(), String> {
    let installer_path = dir.join(PYTHON_INSTALLER);

    emit(
        app,
        "python_install",
        "running",
        &format!("Downloading Python {} (32-bit)...", PYTHON_VERSION),
    );

    // Download
    let response = reqwest::get(PYTHON_URL)
        .await
        .map_err(|e| format!("Download failed: {e}"))?;
    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read download: {e}"))?;

    // Verify MD5
    let digest = format!("{:X}", md5::compute(&bytes));
    if digest != PYTHON_MD5 {
        return Err(format!(
            "Python installer MD5 mismatch (got {digest}, expected {PYTHON_MD5}). \
             Please try again."
        ));
    }

    std::fs::write(&installer_path, &bytes).map_err(|e| e.to_string())?;

    emit(app, "python_install", "running", "Running installer silently, please wait...");
    emit(app, "uac_prompt", "show", "");

    // Run installer silently for all users
    let log_path = dir.join("python-install.log");
    let mut installer_cmd = tokio::process::Command::new(&installer_path);
    installer_cmd.args(["/quiet", "InstallAllUsers=1", "PrependPath=0", "Include_test=0"]);
    installer_cmd.arg("/log");
    installer_cmd.arg(&log_path);
    no_window(&mut installer_cmd);
    let status = installer_cmd
        .status()
        .await
        .map_err(|e| format!("Failed to run installer: {e}"))?;

    // Clean up the installer exe regardless of outcome
    let _ = std::fs::remove_file(&installer_path);

    if !status.success() {
        return Err(format!(
            "Python installer exited with an error. If your antivirus blocked it, \
             add an exclusion for this folder and try again. \
             Installer log: {}",
            log_path.display()
        ));
    }

    // Install succeeded — remove all python-install* files
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("python-install") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    Ok(())
}

/// Create the virtual environment using the 32-bit Python binary.
async fn setup_venv(python_exe: &PathBuf, venv_dir: &PathBuf) -> Result<(), String> {
    if venv_dir.join("Scripts").join("python.exe").exists() {
        return Ok(()); // already exists
    }

    // Remove partial venv if present
    if venv_dir.exists() {
        std::fs::remove_dir_all(venv_dir).map_err(|e| e.to_string())?;
    }

    let mut venv_cmd = tokio::process::Command::new(python_exe);
    venv_cmd.args(["-m", "venv"]).arg(venv_dir);
    no_window(&mut venv_cmd);
    let status = venv_cmd
        .status()
        .await
        .map_err(|e| format!("Failed to create venv: {e}"))?;

    if !status.success() {
        return Err(
            "Failed to create virtual environment. If your antivirus is blocking Python, \
             add a folder exclusion for this directory."
                .to_string(),
        );
    }
    Ok(())
}

/// Find pyproject.toml by walking up from the exe directory.
fn find_pyproject(exe_dir: &PathBuf) -> Option<PathBuf> {
    let mut dir = exe_dir.clone();
    for _ in 0..4 {
        let candidate = dir.join("pyproject.toml");
        if candidate.exists() {
            return std::fs::canonicalize(&candidate).ok().or(Some(candidate));
        }
        dir = dir.join("..");
    }
    None
}

/// Run pip install if pyproject.toml has changed since last install.
/// Emits line-by-line pip output as "info" events.
async fn install_deps(app: &tauri::AppHandle, venv_dir: &PathBuf, exe_dir: &PathBuf) -> Result<(), String> {
    let pyproject_path = match find_pyproject(exe_dir) {
        Some(p) => p,
        None => {
            // No pyproject.toml found — assume venv is pre-built, skip install
            return Ok(());
        }
    };

    let pyproject_dir = pyproject_path
        .parent()
        .ok_or("Could not get pyproject.toml parent directory")?
        .to_path_buf();

    // Read and hash pyproject.toml
    let content = std::fs::read(&pyproject_path).map_err(|e| e.to_string())?;
    let current_hash = format!("{:X}", md5::compute(&content));

    let hash_file = venv_dir.join(".requirements_hash");
    let stored_hash = std::fs::read_to_string(&hash_file).unwrap_or_default();

    if current_hash == stored_hash.trim() {
        return Ok(()); // nothing changed
    }

    let pip_exe = venv_dir.join("Scripts").join("pip.exe");

    let mut pip_cmd = tokio::process::Command::new(&pip_exe);
    pip_cmd
        .args(["install", "--disable-pip-version-check", ".", "--quiet"])
        .current_dir(&pyproject_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    no_window(&mut pip_cmd);
    let mut child = pip_cmd.spawn().map_err(|e| format!("Failed to launch pip: {e}"))?;

    // Stream stdout
    if let Some(stdout) = child.stdout.take() {
        let mut lines = BufReader::new(stdout).lines();
        let app_clone = app.clone();
        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                emit(&app_clone, "pip_output", "info", &line);
            }
        });
    }

    // Stream stderr
    if let Some(stderr) = child.stderr.take() {
        let mut lines = BufReader::new(stderr).lines();
        let app_clone = app.clone();
        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                emit(&app_clone, "pip_output", "info", &line);
            }
        });
    }

    let status = child.wait().await.map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("pip install failed. Please try again.".to_string());
    }

    // Store hash for next run
    let _ = std::fs::write(&hash_file, &current_hash);
    Ok(())
}

/// Verify that pykakasi can be imported from the venv.
async fn verify_install(venv_dir: &PathBuf) -> Result<(), String> {
    let python = venv_dir.join("Scripts").join("python.exe");
    let mut verify_cmd = tokio::process::Command::new(&python);
    verify_cmd.args(["-c", "import pykakasi"]);
    no_window(&mut verify_cmd);
    let status = verify_cmd
        .status()
        .await
        .map_err(|e| format!("Failed to run verification: {e}"))?;

    if !status.success() {
        return Err(
            "Dependency verification failed. The virtual environment may be corrupt. \
             Please delete the venv folder and try again."
                .to_string(),
        );
    }
    Ok(())
}

/// Run all environment setup steps in sequence, emitting progress events.
#[tauri::command]
pub async fn run_setup(app: tauri::AppHandle) -> Result<(), String> {
    let dir = exe_dir().map_err(|e| {
        emit(&app, "path_check", "error", &e);
        e
    })?;

    let venv_dir = dir.join("venv");

    // Step 1: path safety
    emit(&app, "path_check", "running", "Checking installation path...");
    if let Err(e) = check_path_safety(&dir) {
        emit(&app, "path_check", "error", &e);
        return Err(e);
    }
    emit(&app, "path_check", "done", "Installation path is safe.");

    // Step 2: find Python
    emit(&app, "python_check", "running", "Looking for Python 3.11 (32-bit)...");
    let python_exe = match find_python_exe() {
        Some(p) => {
            emit(&app, "python_check", "done", &format!("Found Python at {}", p.display()));
            p
        }
        None => {
            emit(&app, "python_check", "done", "Python 3.11 (32-bit) not found — will install.");
            if let Err(e) = download_and_install_python(&app, &dir).await {
                emit(&app, "python_install", "error", &e);
                return Err(e);
            }
            emit(&app, "python_install", "done", "Python 3.11.3 installed successfully.");
            match find_python_exe() {
                Some(p) => p,
                None => {
                    let msg = "Python was installed but could not be located. Please restart the launcher.";
                    emit(&app, "python_install", "error", msg);
                    return Err(msg.to_string());
                }
            }
        }
    };

    // Step 3: virtual environment
    emit(&app, "venv_setup", "running", "Setting up virtual environment...");
    if let Err(e) = setup_venv(&python_exe, &venv_dir).await {
        emit(&app, "venv_setup", "error", &e);
        return Err(e);
    }
    emit(&app, "venv_setup", "done", "Virtual environment ready.");

    // Step 4: install dependencies
    emit(&app, "deps_install", "running", "Checking dependencies...");
    if let Err(e) = install_deps(&app, &venv_dir, &dir).await {
        emit(&app, "deps_install", "error", &e);
        return Err(e);
    }
    emit(&app, "deps_install", "done", "Dependencies are up to date.");

    // Step 5: verify
    emit(&app, "verify", "running", "Verifying installation...");
    if let Err(e) = verify_install(&venv_dir).await {
        emit(&app, "verify", "error", &e);
        return Err(e);
    }
    emit(&app, "verify", "done", "Installation verified.");

    Ok(())
}
