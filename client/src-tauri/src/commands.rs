//! Tauri IPC commands.
//!
//! These commands are called from the frontend JavaScript via `window.__TAURI__.invoke()`.
//! Each command interacts with the WebSocket client and crypto layer.
//!
//! All messages are encrypted client-side before being sent to the server.
//! The server never sees plaintext.

use std::sync::Arc;

use tauri::State;

use retro_crypto::encryption;
use retro_crypto::registry::{ServerInfo, ServerListEntry, ServerListResponse};
use retro_crypto::{ClientMessage, RoomConfig};

use crate::ws::{self, ClientState};

// ─── Server Discovery ───────────────────────────────────────────────────────

/// Fetch the server list from the central registry.
#[tauri::command]
pub async fn fetch_servers(
    registry_url: Option<String>,
    official_only: Option<bool>,
) -> Result<Vec<ServerListEntry>, String> {
    let base = registry_url.unwrap_or_else(|| "https://registry.retro.chat".to_string());
    let official = official_only.unwrap_or(false);
    let url = format!(
        "{}/api/servers?official_only={}",
        base.trim_end_matches('/'),
        official
    );

    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("Failed to reach registry: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Registry returned status {}", resp.status()));
    }

    let body: ServerListResponse = resp
        .json()
        .await
        .map_err(|e| format!("Invalid response from registry: {}", e))?;

    Ok(body.servers)
}

/// Query a specific server's /info endpoint.
#[tauri::command]
pub async fn fetch_server_info(address: String) -> Result<ServerInfo, String> {
    let url = if address.starts_with("http://") || address.starts_with("https://") {
        format!("{}/info", address.trim_end_matches('/'))
    } else {
        format!("http://{}/info", address)
    };

    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("Failed to reach server: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Server returned status {}", resp.status()));
    }

    let info: ServerInfo = resp
        .json()
        .await
        .map_err(|e| format!("Invalid response from server: {}", e))?;

    Ok(info)
}

// ─── Connection ─────────────────────────────────────────────────────────────

/// Connect to a Retro server.
///
/// Generates ephemeral session keys (X25519 + Ed25519 + RSA-4096),
/// establishes WebSocket connection, and returns the assigned handle.
#[tauri::command]
pub async fn connect(
    host: String,
    state: State<'_, Arc<ClientState>>,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    if *state.connected.read().await {
        return Err("Already connected to a server".to_string());
    }

    let state_arc = Arc::clone(&*state);
    let handle = ws::connect_to_server(&host, state_arc, app_handle).await?;
    Ok(handle)
}

/// Disconnect from the server and destroy all cryptographic material.
#[tauri::command]
pub async fn disconnect(state: State<'_, Arc<ClientState>>) -> Result<(), String> {
    if !*state.connected.read().await {
        return Err("Not connected to any server".to_string());
    }

    ws::disconnect_from_server(&state).await
}

// ─── Rooms ──────────────────────────────────────────────────────────────────

/// Create a new chat room.
///
/// Sends the request to the server. The receive loop handles the
/// `RoomCreated` response: initializes the group key ratchet, publishes
/// our public keys, and emits the `retro://room-created` event.
#[tauri::command]
pub async fn create_room(
    name: String,
    msg_expiry: Option<u64>,
    file_expiry: Option<u64>,
    state: State<'_, Arc<ClientState>>,
) -> Result<(), String> {
    if !*state.connected.read().await {
        return Err("Not connected to any server".to_string());
    }

    let config = RoomConfig {
        name,
        message_expiry_secs: msg_expiry.unwrap_or(0),
        file_expiry_secs: file_expiry.unwrap_or(3600),
    };

    ws::send_message(&state, &ClientMessage::CreateRoom { config }).await
}

/// Join an existing chat room.
///
/// Sends `JoinRoom` followed by `PublishKeys` so existing members can
/// initiate key exchange. The receive loop handles:
/// - `RoomJoined`: stores member keys, derives DM keys
/// - `KeyExchange`: completes exchange, recovers group key
#[tauri::command]
pub async fn join_room(
    room_id: String,
    state: State<'_, Arc<ClientState>>,
) -> Result<(), String> {
    if !*state.connected.read().await {
        return Err("Not connected to any server".to_string());
    }

    // Send JoinRoom
    ws::send_message(
        &state,
        &ClientMessage::JoinRoom {
            room_id: room_id.clone(),
        },
    )
    .await?;

    // Publish our public keys so existing members can initiate key exchange
    let bundle = {
        let keys = state.session_keys.read().await;
        match &*keys {
            Some(k) => k
                .public_bundle()
                .map_err(|e| format!("Failed to get public key bundle: {}", e))?,
            None => return Err("No session keys available".to_string()),
        }
    };

    ws::send_message(
        &state,
        &ClientMessage::PublishKeys {
            room_id,
            public_keys: bundle,
        },
    )
    .await
}

/// Leave the current room. Zeroizes all room-related crypto state.
#[tauri::command]
pub async fn leave_room(state: State<'_, Arc<ClientState>>) -> Result<(), String> {
    let room_id = state
        .current_room
        .read()
        .await
        .clone()
        .ok_or("Not in any room")?;

    ws::send_message(&state, &ClientMessage::LeaveRoom { room_id }).await?;

    // Zeroize room-related crypto state
    *state.current_room.write().await = None;
    *state.group_ratchet.write().await = None;
    state.members.write().await.clear();
    state.dm_keys.write().await.clear();

    Ok(())
}

/// Close the current room (creator only). Triggers cryptographic death.
#[tauri::command]
pub async fn close_room(state: State<'_, Arc<ClientState>>) -> Result<(), String> {
    let room_id = state
        .current_room
        .read()
        .await
        .clone()
        .ok_or("Not in any room")?;

    ws::send_message(&state, &ClientMessage::CloseRoom { room_id }).await?;

    // Zeroize everything room-related
    *state.current_room.write().await = None;
    *state.group_ratchet.write().await = None;
    state.members.write().await.clear();
    state.dm_keys.write().await.clear();

    Ok(())
}

// ─── Chat ───────────────────────────────────────────────────────────────────

/// Send an encrypted message to the current room.
///
/// Encrypts with the group key via double-wrap:
/// plaintext → XChaCha20-Poly1305 → AES-256-GCM → ciphertext
#[tauri::command]
pub async fn send_message(
    text: String,
    state: State<'_, Arc<ClientState>>,
) -> Result<(), String> {
    let room_id = state
        .current_room
        .read()
        .await
        .clone()
        .ok_or("Not in any room")?;

    let payload = {
        let ratchet = state.group_ratchet.read().await;
        let r = ratchet
            .as_ref()
            .ok_or("No group key — waiting for key exchange")?;
        encryption::encrypt(text.as_bytes(), r.current_key(), r.epoch())
            .map_err(|e| format!("Encryption failed: {}", e))?
    };

    ws::send_message(&state, &ClientMessage::SendMessage { room_id, payload }).await
}

/// Send an encrypted DM to a specific member within the current room.
///
/// Uses a per-recipient DM key derived via ECDH + HKDF.
/// Double-wrapped just like group messages.
#[tauri::command]
pub async fn send_dm(
    recipient: String,
    message: String,
    state: State<'_, Arc<ClientState>>,
) -> Result<(), String> {
    let room_id = state
        .current_room
        .read()
        .await
        .clone()
        .ok_or("Not in any room")?;

    let payload = {
        let dm_keys = state.dm_keys.read().await;
        let dm_key = dm_keys.get(&recipient).ok_or(format!(
            "No DM key for {} — they haven't published keys yet",
            recipient
        ))?;
        encryption::encrypt(message.as_bytes(), dm_key, 0)
            .map_err(|e| format!("Encryption failed: {}", e))?
    };

    ws::send_message(
        &state,
        &ClientMessage::DirectMessage {
            room_id,
            recipient,
            payload,
        },
    )
    .await
}

/// List members in the current room.
#[tauri::command]
pub async fn list_members(state: State<'_, Arc<ClientState>>) -> Result<Vec<String>, String> {
    if state.current_room.read().await.is_none() {
        return Err("Not in any room".to_string());
    }

    let members = state.members.read().await;
    let handles: Vec<String> = members.keys().cloned().collect();
    Ok(handles)
}

// ─── Files ──────────────────────────────────────────────────────────────────

/// Upload an encrypted file to the current room.
///
/// Reads the file, encrypts both content and filename with the group key,
/// then sends via WebSocket.
#[tauri::command]
pub async fn upload_file(
    path: String,
    state: State<'_, Arc<ClientState>>,
) -> Result<(), String> {
    let room_id = state
        .current_room
        .read()
        .await
        .clone()
        .ok_or("Not in any room")?;

    // Read file from disk
    let file_data = tokio::fs::read(&path)
        .await
        .map_err(|e| format!("Failed to read file: {}", e))?;

    let file_name = std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let file_id = format!("file_{:016x}", rand::random::<u64>());

    // Encrypt file content and filename with group key
    let (payload, encrypted_name) = {
        let ratchet = state.group_ratchet.read().await;
        let r = ratchet
            .as_ref()
            .ok_or("No group key — waiting for key exchange")?;

        let payload = encryption::encrypt(&file_data, r.current_key(), r.epoch())
            .map_err(|e| format!("File encryption failed: {}", e))?;

        let name_payload =
            encryption::encrypt(file_name.as_bytes(), r.current_key(), r.epoch())
                .map_err(|e| format!("Filename encryption failed: {}", e))?;

        // Store encrypted name as JSON so it can be decrypted later
        let encrypted_name = serde_json::to_string(&name_payload)
            .map_err(|e| format!("Serialization: {}", e))?;

        (payload, encrypted_name)
    };

    let file = retro_crypto::EncryptedFile {
        file_id,
        encrypted_name,
        size: file_data.len() as u64,
        payload,
    };

    ws::send_message(&state, &ClientMessage::UploadFile { room_id, file }).await
}

/// Download and decrypt a file from the current room.
///
/// Registers the save path, then sends the download request.
/// The receive loop handles the `FileData` response: decrypts and saves.
#[tauri::command]
pub async fn download_file(
    file_id: String,
    save_path: String,
    state: State<'_, Arc<ClientState>>,
) -> Result<(), String> {
    let room_id = state
        .current_room
        .read()
        .await
        .clone()
        .ok_or("Not in any room")?;

    // Store the save path for when FileData arrives in the receive loop
    state
        .pending_downloads
        .write()
        .await
        .insert(file_id.clone(), save_path);

    ws::send_message(
        &state,
        &ClientMessage::DownloadFile { room_id, file_id },
    )
    .await
}

// ─── Window Controls ────────────────────────────────────────────────────────

/// Minimize the application window.
#[tauri::command]
pub async fn window_minimize(window: tauri::WebviewWindow) -> Result<(), String> {
    window.minimize().map_err(|e| e.to_string())
}

/// Toggle maximize/unmaximize the application window.
#[tauri::command]
pub async fn window_maximize_toggle(window: tauri::WebviewWindow) -> Result<(), String> {
    if window.is_maximized().map_err(|e| e.to_string())? {
        window.unmaximize().map_err(|e| e.to_string())
    } else {
        window.maximize().map_err(|e| e.to_string())
    }
}

/// Close the application window.
#[tauri::command]
pub async fn window_close(window: tauri::WebviewWindow) -> Result<(), String> {
    window.close().map_err(|e| e.to_string())
}

/// Begin window drag.
#[tauri::command]
pub async fn window_start_drag(window: tauri::WebviewWindow) -> Result<(), String> {
    window.start_dragging().map_err(|e| e.to_string())
}
