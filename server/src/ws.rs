//! WebSocket handler.
//!
//! Handles WebSocket upgrade, connection lifecycle, and message routing.
//! The server acts as a DUMB RELAY — it routes encrypted blobs between
//! clients without any ability to read or modify them.
//!
//! ## Access Control
//!
//! While the server cannot read messages, it DOES enforce:
//! - Connection limits (max_players)
//! - Room membership (only members can send/receive in a room)
//! - Room creation limits (max_rooms)
//! - Message size limits
//! - Per-connection rate limiting
//!
//! ## Connection Lifecycle
//!
//! 1. Client connects via WebSocket
//! 2. Server assigns ephemeral handle, sends `Identity` message
//! 3. Client joins/creates rooms, exchanges keys with peers
//! 4. Server relays encrypted messages between room members
//! 5. Client disconnects — server removes from all rooms, triggers ratchet notifications

use std::time::Instant;

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use retro_crypto::{ClientMessage, RoomListEntry, ServerMessage};

use crate::state::AppState;

/// Per-connection rate limiter.
///
/// Uses a simple token bucket: `tokens_per_second` tokens refill per second,
/// max `burst` tokens. Each message costs 1 token.
struct RateLimiter {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(messages_per_second: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            max_tokens: burst,
            refill_rate: messages_per_second,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume a token. Returns false if rate limited.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// HTTP → WebSocket upgrade handler.
///
/// Enforces max_players limit before accepting the connection.
pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    // Enforce connection limit
    if !state.can_accept_connection() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Server is full",
        )
            .into_response();
    }
    ws.on_upgrade(move |socket| handle_connection(socket, state))
        .into_response()
}

/// Handle a single WebSocket connection.
async fn handle_connection(socket: WebSocket, state: AppState) {
    // Track connection for player count
    state.on_connect();

    // Generate ephemeral handle
    let handle = retro_crypto::keys::generate_handle();
    tracing::info!("New connection established");

    // Split socket into sender and receiver
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Create a channel for sending messages to this client
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Send identity to client
    let identity_msg = serde_json::to_string(&ServerMessage::Identity {
        handle: handle.clone(),
    })
    .unwrap();
    let _ = ws_sender.send(Message::Text(identity_msg.into())).await;

    // Spawn task to forward messages from channel to WebSocket
    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Receive and route messages from client
    let recv_state = state.clone();
    let recv_handle = handle.clone();
    let recv_tx = tx.clone();
    let max_msg_size = state.max_message_size();
    let mut recv_task = tokio::spawn(async move {
        let mut rooms: Vec<String> = Vec::new();
        let tx = recv_tx;

        // Rate limiter: 10 messages/sec with burst of 20
        let mut rate_limiter = RateLimiter::new(10.0, 20.0);
        // Room creation rate limiter: 1 room/sec with burst of 3
        let mut room_rate_limiter = RateLimiter::new(1.0, 3.0);

        while let Some(Ok(msg)) = ws_receiver.next().await {
            match msg {
                Message::Text(text) => {
                    // Enforce message size limit
                    if text.len() > max_msg_size {
                        let _ = tx.send(
                            serde_json::to_string(&ServerMessage::Error {
                                message: "Message too large".to_string(),
                            })
                            .unwrap(),
                        );
                        continue;
                    }

                    // Enforce rate limit
                    if !rate_limiter.allow() {
                        let _ = tx.send(
                            serde_json::to_string(&ServerMessage::Error {
                                message: "Rate limited — slow down".to_string(),
                            })
                            .unwrap(),
                        );
                        continue;
                    }

                    let client_msg = match serde_json::from_str::<ClientMessage>(&text) {
                        Ok(m) => m,
                        Err(e) => {
                            let _ = tx.send(
                                serde_json::to_string(&ServerMessage::Error {
                                    message: format!("Invalid message: {}", e),
                                })
                                .unwrap(),
                            );
                            continue;
                        }
                    };

                    match client_msg {
                        // ── Create Room ──────────────────────────────────
                        ClientMessage::CreateRoom { config } => {
                            if !room_rate_limiter.allow() {
                                let _ = tx.send(
                                    serde_json::to_string(&ServerMessage::Error {
                                        message: "Room creation rate limited".to_string(),
                                    })
                                    .unwrap(),
                                );
                                continue;
                            }

                            if !recv_state.can_create_room() {
                                let _ = tx.send(
                                    serde_json::to_string(&ServerMessage::Error {
                                        message: "Server room limit reached".to_string(),
                                    })
                                    .unwrap(),
                                );
                                continue;
                            }

                            let room_id = recv_state.create_room(config.clone());
                            rooms.push(room_id.clone());

                            // Add creator to room
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                room.add_member(recv_handle.clone(), tx.clone()).await;
                            }

                            let created_at = recv_state.rooms().get(&room_id)
                                .map(|r| r.created_at).unwrap_or(0);

                            let response = serde_json::to_string(&ServerMessage::RoomCreated {
                                room_id,
                                created_at,
                            })
                            .unwrap();
                            let _ = tx.send(response);
                        }

                        // ── Join Room ────────────────────────────────────
                        ClientMessage::JoinRoom { room_id, password_hash } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                // Check room capacity
                                if !room.can_accept_member().await {
                                    let _ = tx.send(
                                        serde_json::to_string(&ServerMessage::Error {
                                            message: "Room is full".to_string(),
                                        })
                                        .unwrap(),
                                    );
                                    continue;
                                }

                                // Verify password if the room has one.
                                // The stored password is an Argon2id PHC string.
                                // The client sends a plaintext password, which we
                                // verify against the stored hash.
                                if !room.config.password.is_empty() {
                                    if !retro_crypto::verify_password(&password_hash, &room.config.password) {
                                        let _ = tx.send(
                                            serde_json::to_string(&ServerMessage::Error {
                                                message: "Incorrect room password".to_string(),
                                            })
                                            .unwrap(),
                                        );
                                        continue;
                                    }
                                }

                                // Get existing members before we join
                                let member_list =
                                    room.get_member_infos(None).await;

                                rooms.push(room_id.clone());
                                room.add_member(recv_handle.clone(), tx.clone()).await;

                                let is_creator = room.is_creator(&recv_handle).await;
                                let created_at = room.created_at;

                                let response =
                                    serde_json::to_string(&ServerMessage::RoomJoined {
                                        room_id,
                                        members: member_list,
                                        config: room.config.clone(),
                                        is_creator,
                                        created_at,
                                    })
                                    .unwrap();
                                let _ = tx.send(response);
                            } else {
                                let _ = tx.send(
                                    serde_json::to_string(&ServerMessage::Error {
                                        message: "Room not found".to_string(),
                                    })
                                    .unwrap(),
                                );
                            }
                        }

                        // ── Publish Keys ─────────────────────────────────
                        ClientMessage::PublishKeys {
                            room_id,
                            public_keys,
                        } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                // Membership check
                                if !room.is_member(&recv_handle).await {
                                    continue;
                                }

                                room.set_member_keys(&recv_handle, public_keys.clone())
                                    .await;

                                let msg =
                                    serde_json::to_string(&ServerMessage::MemberKeys {
                                        room_id,
                                        from: recv_handle.clone(),
                                        public_keys,
                                    })
                                    .unwrap();
                                room.broadcast_except(&msg, &recv_handle).await;
                            }
                        }

                        // ── Key Exchange ──────────────────────────────────
                        ClientMessage::KeyExchange {
                            room_id,
                            recipient,
                            payload,
                        } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                // Membership check
                                if !room.is_member(&recv_handle).await {
                                    continue;
                                }

                                let msg =
                                    serde_json::to_string(&ServerMessage::KeyExchange {
                                        room_id,
                                        from: recv_handle.clone(),
                                        payload,
                                    })
                                    .unwrap();
                                room.send_to_member(&recipient, &msg).await;
                            }
                        }

                        // ── Send Message ─────────────────────────────────
                        ClientMessage::SendMessage { room_id, payload } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                // Membership check — only room members can send
                                if !room.is_member(&recv_handle).await {
                                    let _ = tx.send(
                                        serde_json::to_string(&ServerMessage::Error {
                                            message: "Not a member of this room".to_string(),
                                        })
                                        .unwrap(),
                                    );
                                    continue;
                                }

                                // Store the ciphertext blob
                                let ciphertext_json =
                                    serde_json::to_string(&payload).unwrap();
                                room.store_message(
                                    recv_handle.clone(),
                                    ciphertext_json,
                                )
                                .await;

                                // Broadcast to all members EXCEPT sender
                                let timestamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();

                                let msg =
                                    serde_json::to_string(&ServerMessage::Message {
                                        room_id,
                                        from: recv_handle.clone(),
                                        payload,
                                        timestamp,
                                    })
                                    .unwrap();
                                room.broadcast_except(&msg, &recv_handle).await;
                            }
                        }

                        // ── Direct Message ───────────────────────────────
                        ClientMessage::DirectMessage {
                            room_id,
                            recipient,
                            payload,
                        } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                // Membership check
                                if !room.is_member(&recv_handle).await {
                                    continue;
                                }

                                let msg =
                                    serde_json::to_string(&ServerMessage::DirectMessage {
                                        room_id,
                                        from: recv_handle.clone(),
                                        payload,
                                    })
                                    .unwrap();
                                room.send_to_member(&recipient, &msg).await;
                            }
                        }

                        // ── Leave Room ───────────────────────────────────
                        ClientMessage::LeaveRoom { room_id } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                let is_empty = room.remove_member(&recv_handle).await;
                                // Auto-destroy empty rooms
                                if is_empty {
                                    drop(room);
                                    recv_state.destroy_room(&room_id);
                                }
                            }
                            rooms.retain(|r| r != &room_id);
                        }

                        // ── Close Room (creator only) ────────────────────
                        ClientMessage::CloseRoom { room_id } => {
                            let is_creator = if let Some(room) =
                                recv_state.rooms().get(&room_id)
                            {
                                room.is_creator(&recv_handle).await
                            } else {
                                false
                            };

                            if is_creator {
                                // Notify all members before destruction
                                if let Some(room) =
                                    recv_state.rooms().get(&room_id)
                                {
                                    let close_msg = serde_json::to_string(
                                        &ServerMessage::RoomClosed {
                                            room_id: room_id.clone(),
                                        },
                                    )
                                    .unwrap();
                                    room.broadcast(&close_msg).await;
                                }

                                // Cryptographic death
                                recv_state.destroy_room(&room_id);
                                rooms.retain(|r| r != &room_id);
                            } else {
                                let _ = tx.send(
                                    serde_json::to_string(&ServerMessage::Error {
                                        message:
                                            "Only the room creator can close the room"
                                                .to_string(),
                                    })
                                    .unwrap(),
                                );
                            }
                        }

                        // ── List Rooms ───────────────────────────────────
                        ClientMessage::ListRooms => {
                            let mut entries = Vec::new();
                            for entry in recv_state.rooms().iter() {
                                let room = entry.value();
                                // Skip hidden rooms and password-protected rooms
                                if room.config.hidden || !room.config.password.is_empty() {
                                    continue;
                                }
                                let count = room.members.read().await.len() as u32;
                                entries.push(RoomListEntry {
                                    room_id: room.id.clone(),
                                    name: if room.config.name.is_empty() {
                                        room.id[..16.min(room.id.len())].to_string()
                                    } else {
                                        room.config.name.clone()
                                    },
                                    member_count: count,
                                    created_at: room.created_at,
                                });
                            }
                            let response = serde_json::to_string(
                                &ServerMessage::RoomList { rooms: entries },
                            )
                            .unwrap();
                            let _ = tx.send(response);
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        rooms
    });

    // Wait for either task to finish
    tokio::select! {
        _ = &mut send_task => {
            recv_task.abort();
        }
        result = &mut recv_task => {
            send_task.abort();
            // Clean up: remove from all joined rooms on disconnect
            if let Ok(rooms) = result {
                for room_id in &rooms {
                    if let Some(room) = state.rooms().get(room_id) {
                        let is_empty = room.remove_member(&handle).await;
                        if is_empty {
                            drop(room);
                            state.destroy_room(room_id);
                        }
                    }
                }
            }
        }
    }

    tracing::info!("Connection closed");
    state.on_disconnect();
}
