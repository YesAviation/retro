//! # Retro Client
//!
//! Tauri application backend for the Retro anonymous chat client.
//!
//! Responsibilities:
//! - Manage WebSocket connection to the Retro server
//! - Handle all cryptographic operations (key generation, encryption, decryption)
//! - Expose IPC commands to the frontend terminal UI
//! - Ensure all key material is zeroized on disconnect

mod commands;
mod ws;

use std::sync::Arc;

use tauri::Manager;

/// Run the Tauri application.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            commands::fetch_servers,
            commands::fetch_server_info,
            commands::connect,
            commands::disconnect,
            commands::create_room,
            commands::join_room,
            commands::leave_room,
            commands::close_room,
            commands::list_rooms,
            commands::send_message,
            commands::send_dm,
            commands::list_members,
            commands::upload_file,
            commands::download_file,
            commands::window_minimize,
            commands::window_maximize_toggle,
            commands::window_close,
            commands::window_start_drag,
        ])
        .setup(|app| {
            // Initialize client state wrapped in Arc for shared ownership
            app.manage(Arc::new(ws::ClientState::new()));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Retro");
}
