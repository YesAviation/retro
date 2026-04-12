//! WebSocket client for connecting to the Retro server.
//!
//! Manages the persistent WebSocket connection, incoming message routing,
//! and connection lifecycle. All cryptographic operations happen here
//! on the client side — the server never sees plaintext.

use std::collections::HashMap;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;

use retro_crypto::encryption;
use retro_crypto::exchange;
use retro_crypto::ratchet::GroupKeyRatchet;
use retro_crypto::{ClientMessage, ServerMessage, SessionKeys};

// ─── Client State ───────────────────────────────────────────────────────────

/// Client-side connection state.
///
/// Wrapped in `Arc` and managed by Tauri's state system.
/// All fields use `RwLock` for safe concurrent access between
/// command handlers (Tauri thread) and the receive loop (tokio task).
pub struct ClientState {
    /// Our ephemeral handle (assigned by server)
    pub handle: RwLock<Option<String>>,
    /// Current room ID
    pub current_room: RwLock<Option<String>>,
    /// WebSocket sender channel — send JSON strings to the server
    pub ws_sender: RwLock<Option<mpsc::UnboundedSender<String>>>,
    /// Connection status
    pub connected: RwLock<bool>,
    /// Our ephemeral session keys (X25519 + Ed25519 + RSA-4096)
    pub session_keys: RwLock<Option<SessionKeys>>,
    /// Group key ratchet for the current room (forward secrecy)
    pub group_ratchet: RwLock<Option<GroupKeyRatchet>>,
    /// Known members in current room: handle → public key bundle
    pub members: RwLock<HashMap<String, retro_crypto::PublicKeyBundle>>,
    /// Per-member DM keys derived via ECDH + HKDF
    pub dm_keys: RwLock<HashMap<String, [u8; 32]>>,
    /// Handle to the receive task (so we can abort on disconnect)
    pub recv_task: RwLock<Option<tokio::task::JoinHandle<()>>>,
}

impl ClientState {
    pub fn new() -> Self {
        Self {
            handle: RwLock::new(None),
            current_room: RwLock::new(None),
            ws_sender: RwLock::new(None),
            connected: RwLock::new(false),
            session_keys: RwLock::new(None),
            group_ratchet: RwLock::new(None),
            members: RwLock::new(HashMap::new()),
            dm_keys: RwLock::new(HashMap::new()),
            recv_task: RwLock::new(None),
        }
    }
}

// ─── Connect / Disconnect ───────────────────────────────────────────────────

/// Connect to a Retro server via WebSocket.
///
/// 1. Establishes WebSocket connection
/// 2. Generates ephemeral session keys (X25519 + Ed25519 + RSA-4096)
/// 3. Waits for Identity message from server
/// 4. Spawns receive loop that routes incoming messages as Tauri events
/// 5. Returns the assigned handle
///
/// ## Transport Security
///
/// Defaults to `wss://` (encrypted WebSocket) unless the caller explicitly
/// specifies `ws://` (e.g., for Tailscale or localhost testing).
pub async fn connect_to_server(
    host: &str,
    state: Arc<ClientState>,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    // Build WebSocket URL — default to encrypted wss://
    // Auto-detect localhost/127.0.0.1/[::1] and use plain ws:// for those
    let ws_url = if host.starts_with("ws://") || host.starts_with("wss://") {
        format!("{}/ws", host.trim_end_matches('/'))
    } else {
        let host_part = host.split(':').next().unwrap_or(host);
        let is_local = matches!(
            host_part,
            "localhost" | "127.0.0.1" | "::1" | "[::1]"
        );
        let scheme = if is_local { "ws" } else { "wss" };
        format!("{}://{}/ws", scheme, host)
    };

    // Connect with timeout to prevent hanging on unreachable servers
    let (ws_stream, _response) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio_tungstenite::connect_async(&ws_url),
    )
    .await
    .map_err(|_| "Connection timed out (10s) — server may be unreachable".to_string())?
    .map_err(|e| format!("WebSocket connection failed: {}", e))?;

    let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

    // Generate ephemeral session keys
    let session_keys =
        SessionKeys::generate().map_err(|e| format!("Key generation failed: {}", e))?;

    // Wait for Identity message from server (with timeout)
    let handle = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match ws_stream_rx.next().await {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(msg) = serde_json::from_str::<ServerMessage>(&text) {
                        if let ServerMessage::Identity { handle } = msg {
                            return Ok(handle);
                        }
                    }
                }
                Some(Err(e)) => return Err(format!("WebSocket error: {}", e)),
                None => return Err("Connection closed before receiving identity".to_string()),
                _ => continue,
            }
        }
    })
    .await
    .map_err(|_| "Server did not send identity within 10s".to_string())??;

    // Create sender channel
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Spawn task to forward outgoing messages to WebSocket
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sink.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Store state
    *state.handle.write().await = Some(handle.clone());
    *state.ws_sender.write().await = Some(tx);
    *state.connected.write().await = true;
    *state.session_keys.write().await = Some(session_keys);
    *state.members.write().await = HashMap::new();
    *state.dm_keys.write().await = HashMap::new();

    // Spawn receive loop with shared state
    let recv_state = Arc::clone(&state);
    let recv_app = app_handle.clone();
    let recv_task = tokio::spawn(async move {
        receive_loop(ws_stream_rx, recv_state, recv_app).await;
    });
    *state.recv_task.write().await = Some(recv_task);

    Ok(handle)
}

/// Disconnect from the server and destroy all keys.
pub async fn disconnect_from_server(state: &ClientState) -> Result<(), String> {
    // Abort receive task
    if let Some(task) = state.recv_task.write().await.take() {
        task.abort();
    }

    // Drop the sender (closes the WebSocket)
    *state.ws_sender.write().await = None;

    // Zeroize session keys (Drop impl handles zeroization)
    *state.session_keys.write().await = None;

    // Zeroize group ratchet (Drop impl handles zeroization)
    *state.group_ratchet.write().await = None;

    // Clear all state
    *state.handle.write().await = None;
    *state.current_room.write().await = None;
    *state.connected.write().await = false;
    *state.members.write().await = HashMap::new();
    *state.dm_keys.write().await = HashMap::new();

    Ok(())
}

// ─── Receive Loop ───────────────────────────────────────────────────────────

/// Background receive loop — parses ServerMessage and emits Tauri events.
///
/// Handles:
/// - **RoomCreated**: Init group key ratchet, publish keys
/// - **RoomJoined**: Store members' public keys, derive DM keys
/// - **MemberJoined**: Ratchet forward (forward secrecy)
/// - **MemberLeft**: Remove member, ratchet forward
/// - **MemberKeys**: Store keys, derive DM key, initiate key exchange
/// - **KeyExchange**: Complete key exchange, recover group key
/// - **Message**: Decrypt with group key, emit plaintext
/// - **DirectMessage**: Decrypt with DM key, emit plaintext
/// - **RoomClosed**: Zeroize all room state
async fn receive_loop<S>(mut stream: S, state: Arc<ClientState>, app: tauri::AppHandle)
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    use tauri::Emitter;

    while let Some(msg_result) = stream.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                let server_msg = match serde_json::from_str::<ServerMessage>(&text) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                match server_msg {
                    // ── Room Created (we are the creator) ────────────────
                    ServerMessage::RoomCreated { room_id, created_at } => {
                        // Initialize fresh group key ratchet
                        match GroupKeyRatchet::new() {
                            Ok(ratchet) => {
                                *state.group_ratchet.write().await = Some(ratchet);
                            }
                            Err(e) => {
                                let _ = app.emit(
                                    "retro://error",
                                    serde_json::json!({
                                        "message": format!("Key ratchet init failed: {}", e)
                                    }),
                                );
                            }
                        }

                        *state.current_room.write().await = Some(room_id.clone());
                        state.members.write().await.clear();
                        state.dm_keys.write().await.clear();

                        // Publish our public keys so future joiners can key-exchange
                        let bundle = {
                            let keys = state.session_keys.read().await;
                            keys.as_ref().and_then(|k| k.public_bundle().ok())
                        };
                        if let Some(bundle) = bundle {
                            send_ws(
                                &state,
                                &ClientMessage::PublishKeys {
                                    room_id: room_id.clone(),
                                    public_keys: bundle,
                                },
                            )
                            .await;
                        }

                        let _ = app.emit(
                            "retro://room-created",
                            serde_json::json!({
                                "room_id": room_id,
                                "is_creator": true,
                                "created_at": created_at,
                            }),
                        );
                    }

                    // ── Room Joined (we joined an existing room) ─────────
                    ServerMessage::RoomJoined {
                        room_id,
                        members,
                        config,
                        is_creator,
                        created_at,
                    } => {
                        // Set current room
                        *state.current_room.write().await = Some(room_id.clone());

                        // Derive DM keys from existing members' public keys
                        let dm_entries: Vec<(String, [u8; 32])> = {
                            let keys = state.session_keys.read().await;
                            if let Some(ref our_keys) = *keys {
                                members
                                    .iter()
                                    .filter(|m| !m.public_keys.x25519.is_empty())
                                    .filter_map(|m| {
                                        exchange::derive_dm_key(our_keys, &m.public_keys)
                                            .ok()
                                            .map(|dk| (m.handle.clone(), dk))
                                    })
                                    .collect()
                            } else {
                                vec![]
                            }
                        };

                        // Store member public keys
                        {
                            let mut mem = state.members.write().await;
                            for m in &members {
                                if !m.public_keys.x25519.is_empty() {
                                    mem.insert(m.handle.clone(), m.public_keys.clone());
                                }
                            }
                        }

                        // Store DM keys
                        {
                            let mut dms = state.dm_keys.write().await;
                            for (handle, key) in dm_entries {
                                dms.insert(handle, key);
                            }
                        }

                        let member_handles: Vec<String> =
                            members.iter().map(|m| m.handle.clone()).collect();
                        let _ = app.emit(
                            "retro://room-joined",
                            serde_json::json!({
                                "room_id": room_id,
                                "members": member_handles,
                                "config": {
                                    "name": config.name,
                                    "message_expiry_secs": config.message_expiry_secs,
                                },
                                "is_creator": is_creator,
                                "created_at": created_at,
                            }),
                        );
                    }

                    // ── Member Joined ────────────────────────────────────
                    ServerMessage::MemberJoined {
                        room_id: _,
                        member,
                    } => {
                        // Ratchet forward — forward secrecy: new member cannot
                        // decrypt messages from before their arrival
                        {
                            let mut ratchet = state.group_ratchet.write().await;
                            if let Some(ref mut r) = *ratchet {
                                let _ = r.ratchet();
                            }
                        }

                        let _ = app.emit(
                            "retro://member-joined",
                            serde_json::json!({ "handle": member.handle }),
                        );
                    }

                    // ── Member Left ──────────────────────────────────────
                    ServerMessage::MemberLeft {
                        room_id: _,
                        handle,
                    } => {
                        // Remove member and their DM key
                        state.members.write().await.remove(&handle);
                        state.dm_keys.write().await.remove(&handle);

                        // Ratchet forward — forward secrecy: departed member
                        // cannot decrypt future messages
                        {
                            let mut ratchet = state.group_ratchet.write().await;
                            if let Some(ref mut r) = *ratchet {
                                let _ = r.ratchet();
                            }
                        }

                        let _ = app.emit(
                            "retro://member-left",
                            serde_json::json!({ "handle": handle }),
                        );
                    }

                    // ── Member Keys (key exchange trigger) ───────────────
                    ServerMessage::MemberKeys {
                        room_id,
                        from,
                        public_keys,
                    } => {
                        // Store their public keys
                        state
                            .members
                            .write()
                            .await
                            .insert(from.clone(), public_keys.clone());

                        // Derive DM key via ECDH + HKDF
                        let dm_key = {
                            let keys = state.session_keys.read().await;
                            keys.as_ref()
                                .and_then(|k| exchange::derive_dm_key(k, &public_keys).ok())
                        };
                        if let Some(dk) = dm_key {
                            state.dm_keys.write().await.insert(from.clone(), dk);
                        }

                        // If we have a group key, initiate key exchange with this member.
                        let payload_to_send = {
                            let keys = state.session_keys.read().await;
                            let ratchet = state.group_ratchet.read().await;
                            match (&*keys, &*ratchet) {
                                (Some(our_keys), Some(r)) => {
                                    exchange::initiate_key_exchange(
                                        our_keys,
                                        &public_keys,
                                        r.current_key(),
                                        r.epoch(),
                                    )
                                    .ok()
                                }
                                _ => None,
                            }
                        };

                        if let Some(payload) = payload_to_send {
                            send_ws(
                                &state,
                                &ClientMessage::KeyExchange {
                                    room_id,
                                    recipient: from,
                                    payload,
                                },
                            )
                            .await;
                        }
                    }

                    // ── Key Exchange (we receive the group key) ──────────
                    ServerMessage::KeyExchange {
                        room_id: _,
                        from,
                        payload,
                    } => {
                        // Complete key exchange — recover the group key
                        let group_key = {
                            let keys = state.session_keys.read().await;
                            let members = state.members.read().await;
                            match (&*keys, members.get(&from)) {
                                (Some(our_keys), Some(sender_keys)) => {
                                    exchange::complete_key_exchange(
                                        our_keys,
                                        sender_keys,
                                        &payload,
                                    )
                                    .ok()
                                }
                                _ => None,
                            }
                        };

                        if let Some(key) = group_key {
                            let epoch = payload.encrypted_group_key.epoch;
                            *state.group_ratchet.write().await =
                                Some(GroupKeyRatchet::from_key(key, epoch));
                            let _ = app.emit(
                                "retro://system",
                                serde_json::json!({
                                    "message": "End-to-end encryption established."
                                }),
                            );
                        }
                    }

                    // ── Incoming Message (decrypt with group key) ────────
                    ServerMessage::Message {
                        room_id: _,
                        from,
                        payload,
                        timestamp: _,
                    } => {
                        let text = {
                            let ratchet = state.group_ratchet.read().await;
                            match &*ratchet {
                                Some(r) => {
                                    match encryption::decrypt(&payload, r.current_key()) {
                                        Ok(bytes) => {
                                            String::from_utf8_lossy(&bytes).to_string()
                                        }
                                        Err(_) => "[decryption failed]".to_string(),
                                    }
                                }
                                None => "[no group key — key exchange pending]".to_string(),
                            }
                        };

                        let _ = app.emit(
                            "retro://message",
                            serde_json::json!({ "from": from, "text": text }),
                        );
                    }

                    // ── Incoming DM (decrypt with per-member DM key) ─────
                    ServerMessage::DirectMessage {
                        room_id: _,
                        from,
                        payload,
                    } => {
                        let text = {
                            let dm_keys = state.dm_keys.read().await;
                            match dm_keys.get(&from) {
                                Some(dk) => {
                                    match encryption::decrypt(&payload, dk) {
                                        Ok(bytes) => {
                                            String::from_utf8_lossy(&bytes).to_string()
                                        }
                                        Err(_) => "[DM decryption failed]".to_string(),
                                    }
                                }
                                None => "[no DM key for this member]".to_string(),
                            }
                        };

                        let _ = app.emit(
                            "retro://dm",
                            serde_json::json!({ "from": from, "text": text }),
                        );
                    }

                    // ── Room Closed (cryptographic death) ────────────────
                    ServerMessage::RoomClosed { room_id } => {
                        *state.current_room.write().await = None;
                        *state.group_ratchet.write().await = None;
                        state.members.write().await.clear();
                        state.dm_keys.write().await.clear();

                        let _ = app.emit(
                            "retro://room-closed",
                            serde_json::json!({ "room_id": room_id }),
                        );
                    }

                    // ── Error ────────────────────────────────────────────
                    ServerMessage::Error { message } => {
                        let _ = app.emit(
                            "retro://error",
                            serde_json::json!({ "message": message }),
                        );
                    }

                    // ── Room List ────────────────────────────────────────
                    ServerMessage::RoomList { rooms } => {
                        let _ = app.emit(
                            "retro://room-list",
                            serde_json::json!({ "rooms": rooms }),
                        );
                    }

                    // Identity handled in connect_to_server
                    _ => {}
                }
            }
            Ok(Message::Close(_)) => break,
            Err(_) => break,
            _ => continue,
        }
    }

    // Connection lost — update state
    *state.connected.write().await = false;
    let _ = app.emit("retro://disconnected", serde_json::json!({}));
}

// ─── Send Helpers ───────────────────────────────────────────────────────────

/// Internal: send a ClientMessage over the WebSocket (fire-and-forget).
async fn send_ws(state: &ClientState, msg: &ClientMessage) {
    let sender = state.ws_sender.read().await;
    if let Some(ref tx) = *sender {
        if let Ok(json) = serde_json::to_string(msg) {
            let _ = tx.send(json);
        }
    }
}

/// Send a ClientMessage JSON over the WebSocket (public API for commands).
pub async fn send_message(state: &ClientState, msg: &ClientMessage) -> Result<(), String> {
    let sender = state.ws_sender.read().await;
    let tx = sender.as_ref().ok_or("Not connected to a server")?;

    let json =
        serde_json::to_string(msg).map_err(|e| format!("Serialization error: {}", e))?;

    tx.send(json)
        .map_err(|e| format!("Failed to send: {}", e))?;

    Ok(())
}
