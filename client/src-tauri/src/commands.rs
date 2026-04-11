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
use retro_crypto::registry::ServerInfo;
use retro_crypto::{ClientMessage, RoomConfig};

use crate::ws::{self, ClientState};

// ─── Server Discovery ───────────────────────────────────────────────────────

/// Query a specific server's /info endpoint.
///
/// Defaults to HTTPS. Use `http://` prefix explicitly for unencrypted
/// connections (e.g., behind Tailscale or on localhost).
#[tauri::command]
pub async fn fetch_server_info(address: String) -> Result<ServerInfo, String> {
    let url = if address.starts_with("http://") || address.starts_with("https://") {
        format!("{}/info", address.trim_end_matches('/'))
    } else {
        // Default to HTTPS for security
        format!("https://{}/info", address)
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
    hidden: Option<bool>,
    password: Option<String>,
    state: State<'_, Arc<ClientState>>,
) -> Result<(), String> {
    if !*state.connected.read().await {
        return Err("Not connected to any server".to_string());
    }

    let config = RoomConfig {
        name,
        message_expiry_secs: msg_expiry.unwrap_or(0),
        hidden: hidden.unwrap_or(false),
        password: match &password {
            Some(p) if !p.is_empty() => retro_crypto::hash_password(p),
            _ => String::new(),
        },
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
    password: Option<String>,
    state: State<'_, Arc<ClientState>>,
) -> Result<(), String> {
    if !*state.connected.read().await {
        return Err("Not connected to any server".to_string());
    }

    // Send password as plaintext — the server verifies it against the
    // stored Argon2id hash. Plaintext never persists on the server.
    let password_hash = match &password {
        Some(p) if !p.is_empty() => p.clone(),
        _ => String::new(),
    };

    // Send JoinRoom
    ws::send_message(
        &state,
        &ClientMessage::JoinRoom {
            room_id: room_id.clone(),
            password_hash,
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

/// Request the list of public rooms from the server.
/// The server responds with a RoomList message, which the receive loop
/// emits as a `retro://room-list` event.
#[tauri::command]
pub async fn list_rooms(state: State<'_, Arc<ClientState>>) -> Result<(), String> {
    if !*state.connected.read().await {
        return Err("Not connected to any server".to_string());
    }

    ws::send_message(&state, &ClientMessage::ListRooms).await
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
