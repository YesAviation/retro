//! Room management.
//!
//! Rooms are the core unit of the Retro server. Each room:
//! - Has a unique ID and configuration (expiry settings)
//! - Tracks connected members (by ephemeral handle only)
//! - Stores encrypted message blobs (ciphertext the server cannot read)
//! - Stores encrypted file blobs with expiry timestamps
//! - Can be destroyed (cryptographic death — all data overwritten)

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;
use tokio::sync::RwLock;

use retro_crypto::{MemberInfo, PublicKeyBundle, RoomConfig, ServerMessage};

/// An active chat room.
#[derive(Debug)]
pub struct Room {
    /// Unique room identifier
    pub id: String,
    /// Room configuration (set by creator)
    pub config: RoomConfig,
    /// Handle of the room creator
    pub creator: RwLock<Option<String>>,
    /// Connected members: handle → member sender channel
    pub members: RwLock<HashMap<String, MemberConnection>>,
    /// Broadcast channel for room-wide messages
    pub broadcast_tx: broadcast::Sender<String>,
    /// Stored encrypted messages (ciphertext blobs)
    pub messages: RwLock<Vec<StoredMessage>>,
    /// Stored encrypted files
    pub files: RwLock<HashMap<String, StoredFile>>,
    /// Room creation timestamp
    pub created_at: u64,
}

/// A connected member's communication channel.
#[derive(Debug, Clone)]
pub struct MemberConnection {
    /// Sender for direct messages to this member
    pub tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Member's public key bundle (for relaying to new joiners)
    pub public_keys: Option<PublicKeyBundle>,
}

/// An encrypted message stored on the server.
///
/// The server has NO ability to decrypt this. It's just bytes.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    /// Serialized encrypted payload (opaque ciphertext)
    pub ciphertext: String,
    /// Timestamp for expiry calculation
    pub timestamp: u64,
    /// Sender's ephemeral handle
    pub from: String,
}

/// An encrypted file stored on the server.
#[derive(Debug)]
pub struct StoredFile {
    /// Serialized encrypted file data (opaque ciphertext)
    pub ciphertext: Vec<u8>,
    /// Upload timestamp for expiry calculation
    pub uploaded_at: u64,
    /// File metadata (encrypted filename, size)
    pub metadata_json: String,
}

impl Room {
    /// Create a new room.
    pub fn new(id: String, config: RoomConfig) -> Self {
        let (broadcast_tx, _) = broadcast::channel(1024);

        Self {
            id,
            config,
            creator: RwLock::new(None),
            members: RwLock::new(HashMap::new()),
            broadcast_tx,
            messages: RwLock::new(Vec::new()),
            files: RwLock::new(HashMap::new()),
            created_at: now(),
        }
    }

    /// Add a member to the room.
    pub async fn add_member(
        &self,
        handle: String,
        tx: tokio::sync::mpsc::UnboundedSender<String>,
    ) {
        let mut members = self.members.write().await;
        members.insert(
            handle.clone(),
            MemberConnection {
                tx: tx.clone(),
                public_keys: None,
            },
        );

        let mut creator = self.creator.write().await;
        if creator.is_none() {
            *creator = Some(handle.clone());
        }

        // Broadcast MemberJoined to all OTHER members (triggers key ratchet on their side)
        let join_msg = serde_json::to_string(&ServerMessage::MemberJoined {
            room_id: self.id.clone(),
            member: MemberInfo {
                handle: handle.clone(),
                public_keys: PublicKeyBundle {
                    x25519: String::new(),
                    ed25519: String::new(),
                    rsa: String::new(),
                },
            },
        })
        .unwrap();

        for (h, conn) in members.iter() {
            if h != &handle {
                let _ = conn.tx.send(join_msg.clone());
            }
        }

        tracing::info!("Member joined room {}: {}", self.id, handle);
    }

    /// Remove a member from the room.
    pub async fn remove_member(&self, handle: &str) {
        let mut members = self.members.write().await;
        members.remove(handle);

        // Broadcast MemberLeft to all remaining members (triggers key ratchet)
        let leave_msg = serde_json::to_string(&ServerMessage::MemberLeft {
            room_id: self.id.clone(),
            handle: handle.to_string(),
        })
        .unwrap();

        for (_, conn) in members.iter() {
            let _ = conn.tx.send(leave_msg.clone());
        }

        tracing::info!("Member left room {}: {}", self.id, handle);
    }

    /// Set a member's public keys (called after PublishKeys message).
    pub async fn set_member_keys(&self, handle: &str, keys: PublicKeyBundle) {
        let mut members = self.members.write().await;
        if let Some(conn) = members.get_mut(handle) {
            conn.public_keys = Some(keys);
        }
    }

    /// Get a list of current members with their public keys.
    pub async fn get_member_infos(&self, exclude_handle: Option<&str>) -> Vec<MemberInfo> {
        let members = self.members.read().await;
        members
            .iter()
            .filter(|(h, _)| {
                if let Some(excl) = exclude_handle {
                    h.as_str() != excl
                } else {
                    true
                }
            })
            .map(|(h, conn)| MemberInfo {
                handle: h.clone(),
                public_keys: conn.public_keys.clone().unwrap_or(PublicKeyBundle {
                    x25519: String::new(),
                    ed25519: String::new(),
                    rsa: String::new(),
                }),
            })
            .collect()
    }

    /// Check if a handle is the room creator.
    pub async fn is_creator(&self, handle: &str) -> bool {
        let creator = self.creator.read().await;
        creator.as_deref() == Some(handle)
    }

    /// Broadcast a serialized message to all room members.
    pub async fn broadcast(&self, message: &str) {
        let members = self.members.read().await;
        for (_, conn) in members.iter() {
            let _ = conn.tx.send(message.to_string());
        }
    }

    /// Broadcast a serialized message to all room members EXCEPT the sender.
    pub async fn broadcast_except(&self, message: &str, except_handle: &str) {
        let members = self.members.read().await;
        for (h, conn) in members.iter() {
            if h != except_handle {
                let _ = conn.tx.send(message.to_string());
            }
        }
    }

    /// Send a direct message to a specific member.
    pub async fn send_to_member(&self, handle: &str, message: &str) {
        let members = self.members.read().await;
        if let Some(member) = members.get(handle) {
            let _ = member.tx.send(message.to_string());
        }
    }

    /// Store an encrypted message blob.
    pub async fn store_message(&self, from: String, ciphertext: String) {
        let mut messages = self.messages.write().await;
        messages.push(StoredMessage {
            ciphertext,
            timestamp: now(),
            from,
        });
    }

    /// Store an encrypted file blob. Returns the expiry timestamp.
    pub async fn store_file(
        &self,
        file_id: String,
        ciphertext: Vec<u8>,
        metadata_json: String,
    ) -> u64 {
        let uploaded_at = now();
        let expires_at = if self.config.file_expiry_secs > 0 {
            uploaded_at + self.config.file_expiry_secs
        } else {
            0 // no expiry
        };
        let mut files = self.files.write().await;
        files.insert(
            file_id,
            StoredFile {
                ciphertext,
                uploaded_at,
                metadata_json,
            },
        );
        expires_at
    }

    /// Retrieve an encrypted file blob by ID.
    pub async fn get_file(&self, file_id: &str) -> Option<Vec<u8>> {
        let files = self.files.read().await;
        files.get(file_id).map(|f| f.ciphertext.clone())
    }

    /// Get the current member count.
    pub async fn member_count(&self) -> usize {
        self.members.read().await.len()
    }

    /// Destroy the room — overwrite all stored data.
    ///
    /// This is **cryptographic death**:
    /// - All stored messages are overwritten with zeros then dropped
    /// - All stored files are overwritten with zeros then dropped
    /// - All member connections are severed
    pub fn destroy(&mut self) {
        // Overwrite all message ciphertext with zeros before dropping
        if let Ok(mut messages) = self.messages.try_write() {
            for msg in messages.iter_mut() {
                // Safety: overwrite the String's buffer with zeros
                let bytes = unsafe { msg.ciphertext.as_mut_vec() };
                bytes.fill(0);
                let from_bytes = unsafe { msg.from.as_mut_vec() };
                from_bytes.fill(0);
            }
            messages.clear();
        }

        // Overwrite all file ciphertext with zeros before dropping
        if let Ok(mut files) = self.files.try_write() {
            for (_, file) in files.iter_mut() {
                file.ciphertext.fill(0);
                let meta_bytes = unsafe { file.metadata_json.as_mut_vec() };
                meta_bytes.fill(0);
            }
            files.clear();
        }

        // Sever all member connections
        if let Ok(mut members) = self.members.try_write() {
            members.clear();
        }

        tracing::info!("Room {} destroyed — cryptographic death", self.id);
    }
}

/// Get current Unix timestamp in seconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
