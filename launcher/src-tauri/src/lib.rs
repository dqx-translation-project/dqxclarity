mod commands;

use commands::process::ProcessState;
use std::sync::Mutex;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
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
            commands::database::read_db_tables,
            commands::database::read_db_table,
            commands::database::delete_db_rows,
            commands::database::purge_dialog_cache,
            commands::process::has_autorun_flag,
            commands::process::minimize_window,
            commands::process::get_version,
            commands::process::read_name_overrides,
            commands::process::save_name_overrides,
            commands::process::launch_clarity,
            commands::process::stop_clarity,
            commands::config::save_theme,
            commands::config::validate_dqx_dir,
            commands::config::save_game_dir,
            commands::config::launch_dqx,
            commands::config::launch_dqx_config,
            commands::update::check_for_updates,
            commands::update::run_updater,
            commands::patch::patch_launcher,
            commands::patch::patch_config,
            commands::patch::restore_launcher,
            commands::patch::restore_config,
            commands::patch::patch_game_files,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
