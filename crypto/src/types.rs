//! Protocol types and message definitions for Retro.
//!
//! These types are shared between client and server, serialized over WebSocket.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ─────────────────────────────────────────────────────────────────

/// Cryptographic errors.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Key exchange failed: {0}")]
    KeyExchange(String),

    #[error("Signature verification failed")]
    SignatureVerification,

    #[error("RSA operation failed: {0}")]
    Rsa(String),

    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Key ratchet error: {0}")]
    Ratchet(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

// ─── Encryption Primitives ──────────────────────────────────────────────────

/// Double-wrapped encrypted payload.
///
/// Inner layer: XChaCha20-Poly1305 (24-byte nonce)
/// Outer layer: AES-256-GCM (12-byte nonce)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// AES-256-GCM nonce (12 bytes, base64)
    pub outer_nonce: String,
    /// XChaCha20-Poly1305 nonce (24 bytes, base64)
    pub inner_nonce: String,
    /// Double-wrapped ciphertext (base64)
    pub ciphertext: String,
    /// Key epoch this was encrypted under
    pub epoch: u64,
}

/// Bundle of ephemeral public keys shared during key exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    /// X25519 public key (32 bytes, base64)
    pub x25519: String,
    /// Ed25519 verifying key (32 bytes, base64)
    pub ed25519: String,
    /// RSA-4096 public key (DER-encoded, base64)
    pub rsa: String,
}

/// Signed and RSA-wrapped key exchange message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangePayload {
    /// X25519 ECDH shared secret, encrypted with recipient's RSA public key (base64)
    pub rsa_wrapped_secret: String,
    /// Group key encrypted with the ECDH shared secret via double-wrap (base64)
    pub encrypted_group_key: EncryptedPayload,
    /// Ed25519 signature over the above fields
    pub signature: String,
}

/// Encrypted file metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFile {
    /// Unique file identifier
    pub file_id: String,
    /// Original filename (encrypted, base64)
    pub encrypted_name: String,
    /// File size in bytes (of the encrypted data)
    pub size: u64,
    /// Double-wrapped file content (base64)
    pub payload: EncryptedPayload,
}

/// File metadata (sent to room members when a file is available).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub file_id: String,
    pub encrypted_name: String,
    pub size: u64,
    pub from: String,
    pub expires_at: u64,
}

// ─── Room Configuration ─────────────────────────────────────────────────────

/// Configuration for a chat room, set by the creator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomConfig {
    /// Human-readable room name (optional, can be empty for anonymous rooms)
    pub name: String,
    /// Message auto-expiry in seconds (0 = no expiry, messages live until room closes)
    pub message_expiry_secs: u64,
    /// File auto-expiry in seconds (0 = no expiry)
    pub file_expiry_secs: u64,
    /// If true, the room will not appear in the public room list
    #[serde(default)]
    pub hidden: bool,
    /// Optional password required to join (empty = no password)
    #[serde(default)]
    pub password: String,
}

impl Default for RoomConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            message_expiry_secs: 0,
            file_expiry_secs: 3600, // 1 hour default
            hidden: false,
            password: String::new(),
        }
    }
}

/// Summary of a room for the public room list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomListEntry {
    /// Unique room ID
    pub room_id: String,
    /// Room display name
    pub name: String,
    /// Number of members currently in the room
    pub member_count: u32,
    /// Room creation timestamp (unix seconds)
    pub created_at: u64,
}

/// Information about a room member (only public keys + handle).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberInfo {
    /// Ephemeral anonymous handle (e.g., "anon_8f3k")
    pub handle: String,
    /// Member's public key bundle for key exchange
    pub public_keys: PublicKeyBundle,
}

// ─── Protocol Messages ──────────────────────────────────────────────────────

/// Messages sent from client → server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ClientMessage {
    /// Create a new chat room
    CreateRoom {
        config: RoomConfig,
    },

    /// Join an existing chat room
    JoinRoom {
        room_id: String,
        /// SHA-256 hash of the room password (empty string hash if no password)
        #[serde(default)]
        password_hash: String,
    },

    /// Publish ephemeral public keys to room members
    PublishKeys {
        room_id: String,
        public_keys: PublicKeyBundle,
    },

    /// Send key exchange payload to a specific member
    KeyExchange {
        room_id: String,
        recipient: String,
        payload: KeyExchangePayload,
    },

    /// Send an encrypted message to the room
    SendMessage {
        room_id: String,
        payload: EncryptedPayload,
    },

    /// Send an encrypted DM to a specific member within a room
    DirectMessage {
        room_id: String,
        recipient: String,
        payload: EncryptedPayload,
    },

    /// Upload an encrypted file to the room
    UploadFile {
        room_id: String,
        file: EncryptedFile,
    },

    /// Request to download a file
    DownloadFile {
        room_id: String,
        file_id: String,
    },

    /// Leave a room
    LeaveRoom {
        room_id: String,
    },

    /// Close a room (creator only) — triggers cryptographic death
    CloseRoom {
        room_id: String,
    },

    /// Request the list of public rooms on this server
    ListRooms,
}

/// Messages sent from server → client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerMessage {
    /// Assigned ephemeral identity on connect
    Identity {
        handle: String,
    },

    /// Room successfully created
    RoomCreated {
        room_id: String,
        created_at: u64,
    },

    /// Successfully joined a room; includes current member list
    RoomJoined {
        room_id: String,
        members: Vec<MemberInfo>,
        config: RoomConfig,
        is_creator: bool,
        created_at: u64,
    },

    /// A new member joined the room — triggers key ratchet
    MemberJoined {
        room_id: String,
        member: MemberInfo,
    },

    /// A member left the room — triggers key ratchet
    MemberLeft {
        room_id: String,
        handle: String,
    },

    /// Incoming public keys from a member (for key exchange)
    MemberKeys {
        room_id: String,
        from: String,
        public_keys: PublicKeyBundle,
    },

    /// Incoming key exchange payload from a member
    KeyExchange {
        room_id: String,
        from: String,
        payload: KeyExchangePayload,
    },

    /// Incoming encrypted room message
    Message {
        room_id: String,
        from: String,
        payload: EncryptedPayload,
        timestamp: u64,
    },

    /// Incoming encrypted DM
    DirectMessage {
        room_id: String,
        from: String,
        payload: EncryptedPayload,
    },

    /// A file is available for download
    FileAvailable {
        room_id: String,
        metadata: FileMetadata,
    },

    /// File data in response to a download request
    FileData {
        file_id: String,
        payload: EncryptedPayload,
    },

    /// Room has been closed — all data destroyed
    RoomClosed {
        room_id: String,
    },

    /// List of public rooms on the server
    RoomList {
        rooms: Vec<RoomListEntry>,
    },

    /// Error message
    Error {
        message: String,
    },
}
