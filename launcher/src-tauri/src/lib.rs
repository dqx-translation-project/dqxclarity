mod commands;

use commands::process::ProcessState;
use std::sync::Mutex;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            use tauri::Manager;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .manage(ProcessState {
            child_id: Mutex::new(None),
            user_stopped: Mutex::new(false),
        })
        .invoke_handler(tauri::generate_handler![
            commands::config::load_config,
            commands::config::save_config,
            commands::config::migrate_ini,
            commands::environment::run_setup,
            commands::validate::validate_deepl_key,
            commands::validate::validate_google_key,
            commands::process::get_version,
            commands::process::launch_clarity,
            commands::process::stop_clarity,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
