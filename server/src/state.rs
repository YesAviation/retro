//! Server-side application state.
//!
//! The server maintains minimal state:
//! - Active rooms (room ID → room data)
//! - Server metadata (name, description, uptime)
//! - Connected client count
//!
//! NO user-identifying information is stored. Handles are ephemeral
//! and randomly generated. No IPs, no fingerprints, no metadata.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use retro_crypto::registry::ServerInfo;

use crate::room::Room;

/// Application state shared across all WebSocket connections.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    /// Active rooms: room_id → Room
    rooms: DashMap<String, Room>,
    /// Server display name
    name: String,
    /// Server description
    description: String,
    /// Maximum players (0 = unlimited)
    max_players: u32,
    /// Number of currently connected WebSocket clients
    connected_count: AtomicU32,
    /// Unix timestamp when the server started
    started_at: u64,
}

impl AppState {
    /// Create a new application state.
    pub fn new(name: String, description: String, max_players: u32) -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                rooms: DashMap::new(),
                name,
                description,
                max_players,
                connected_count: AtomicU32::new(0),
                started_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            }),
        }
    }

    /// Get a reference to the rooms map.
    pub fn rooms(&self) -> &DashMap<String, Room> {
        &self.inner.rooms
    }

    /// Create a new room and return its ID.
    pub fn create_room(&self, config: retro_crypto::RoomConfig) -> String {
        let room_id = uuid::Uuid::new_v4().to_string();
        let room = Room::new(room_id.clone(), config);
        self.inner.rooms.insert(room_id.clone(), room);
        tracing::info!("Room created: {}", room_id);
        room_id
    }

    /// Remove a room and all its data (cryptographic death).
    pub fn destroy_room(&self, room_id: &str) {
        if let Some((_, mut room)) = self.inner.rooms.remove(room_id) {
            room.destroy();
            tracing::info!("Room destroyed: {}", room_id);
        }
    }

    // ─── Connection Tracking ────────────────────────────────────────────

    /// Increment connected client count (called on WebSocket connect).
    pub fn on_connect(&self) {
        self.inner.connected_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement connected client count (called on WebSocket disconnect).
    pub fn on_disconnect(&self) {
        self.inner.connected_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get the current number of connected clients.
    pub fn player_count(&self) -> u32 {
        self.inner.connected_count.load(Ordering::Relaxed)
    }

    // ─── Server Metadata ────────────────────────────────────────────────

    /// Server display name.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Server description.
    pub fn description(&self) -> &str {
        &self.inner.description
    }

    /// Maximum player capacity.
    pub fn max_players(&self) -> u32 {
        self.inner.max_players
    }

    /// Build the ServerInfo response for the /info endpoint.
    pub fn get_server_info(&self) -> ServerInfo {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        ServerInfo {
            name: self.inner.name.clone(),
            description: self.inner.description.clone(),
            room_count: self.inner.rooms.len() as u32,
            player_count: self.player_count(),
            uptime_secs: now.saturating_sub(self.inner.started_at),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}
