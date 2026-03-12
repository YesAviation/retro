//! WebSocket handler.
//!
//! Handles WebSocket upgrade, connection lifecycle, and message routing.
//! The server acts as a DUMB RELAY — it routes encrypted blobs between
//! clients without any ability to read or modify them.
//!
//! ## Connection Lifecycle
//!
//! 1. Client connects via WebSocket
//! 2. Server assigns ephemeral handle, sends `Identity` message
//! 3. Client joins/creates rooms, exchanges keys with peers
//! 4. Server relays encrypted messages between room members
//! 5. Client disconnects — server removes from all rooms, triggers ratchet notifications

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use retro_crypto::{ClientMessage, ServerMessage};

use crate::state::AppState;

/// HTTP → WebSocket upgrade handler.
///
/// Note: We deliberately do NOT log any connection metadata (IP, headers, etc.)
pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_connection(socket, state))
}

/// Handle a single WebSocket connection.
async fn handle_connection(socket: WebSocket, state: AppState) {
    // Track connection for player count
    state.on_connect();

    // Generate ephemeral handle
    let handle = retro_crypto::keys::generate_handle();
    tracing::info!("New connection: {}", handle);

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
    let mut recv_task = tokio::spawn(async move {
        let mut rooms: Vec<String> = Vec::new();
        let tx = recv_tx;

        while let Some(Ok(msg)) = ws_receiver.next().await {
            match msg {
                Message::Text(text) => {
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
                        ClientMessage::JoinRoom { room_id } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
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
                        // Client publishes their ephemeral public keys to room
                        ClientMessage::PublishKeys {
                            room_id,
                            public_keys,
                        } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                // Store keys on the member record
                                room.set_member_keys(&recv_handle, public_keys.clone())
                                    .await;

                                // Relay to all other members so they can initiate key exchange
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
                        // Relay key exchange payload to a specific recipient
                        ClientMessage::KeyExchange {
                            room_id,
                            recipient,
                            payload,
                        } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
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
                        // Store encrypted blob + broadcast to all room members
                        ClientMessage::SendMessage { room_id, payload } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                // Store the ciphertext blob
                                let ciphertext_json =
                                    serde_json::to_string(&payload).unwrap();
                                room.store_message(
                                    recv_handle.clone(),
                                    ciphertext_json,
                                )
                                .await;

                                // Broadcast to all members EXCEPT sender
                                // (sender adds message locally on their side)
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
                        // Relay encrypted DM to specific member
                        ClientMessage::DirectMessage {
                            room_id,
                            recipient,
                            payload,
                        } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
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

                        // ── Upload File ──────────────────────────────────
                        // Store encrypted file blob, notify room
                        ClientMessage::UploadFile { room_id, file } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                let file_id = file.file_id.clone();
                                let metadata_json =
                                    serde_json::to_string(&file).unwrap();
                                let ciphertext =
                                    serde_json::to_string(&file.payload)
                                        .unwrap()
                                        .into_bytes();
                                let size = file.size;
                                let encrypted_name = file.encrypted_name.clone();

                                let expires_at = room
                                    .store_file(
                                        file_id.clone(),
                                        ciphertext,
                                        metadata_json,
                                    )
                                    .await;

                                // Notify all room members that a file is available
                                let notify = serde_json::to_string(
                                    &ServerMessage::FileAvailable {
                                        room_id,
                                        metadata: retro_crypto::FileMetadata {
                                            file_id,
                                            encrypted_name,
                                            size,
                                            from: recv_handle.clone(),
                                            expires_at,
                                        },
                                    },
                                )
                                .unwrap();
                                room.broadcast(&notify).await;
                            }
                        }

                        // ── Download File ────────────────────────────────
                        // Send encrypted file blob to requester
                        ClientMessage::DownloadFile { room_id, file_id } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                if let Some(data) = room.get_file(&file_id).await {
                                    // Parse the stored ciphertext back to EncryptedPayload
                                    if let Ok(payload) = serde_json::from_slice::<
                                        retro_crypto::EncryptedPayload,
                                    >(&data)
                                    {
                                        let msg = serde_json::to_string(
                                            &ServerMessage::FileData {
                                                file_id,
                                                payload,
                                            },
                                        )
                                        .unwrap();
                                        let _ = tx.send(msg);
                                    }
                                } else {
                                    let _ = tx.send(
                                        serde_json::to_string(&ServerMessage::Error {
                                            message: format!(
                                                "File not found: {}",
                                                file_id
                                            ),
                                        })
                                        .unwrap(),
                                    );
                                }
                            }
                        }

                        // ── Leave Room ───────────────────────────────────
                        ClientMessage::LeaveRoom { room_id } => {
                            if let Some(room) = recv_state.rooms().get(&room_id) {
                                room.remove_member(&recv_handle).await;
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
                        room.remove_member(&handle).await;
                        // MemberLeft broadcast happens inside remove_member,
                        // which triggers key ratchet on remaining members
                    }
                }
            }
        }
    }

    tracing::info!("Connection closed: {}", handle);
    state.on_disconnect();
}
