//! Server info types for the Retro server discovery.
//!
//! Used by:
//! - **retro-server** — serves the `/info` endpoint
//! - **retro-client** — queries server info before connecting

use serde::{Deserialize, Serialize};

// ─── Server Info (Server → Client, direct) ──────────────────────────────────

/// Server info returned by the GET /info endpoint on each server.
///
/// Clients can query this directly via HTTP before connecting via WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Server display name
    pub name: String,
    /// Optional description
    pub description: String,
    /// Number of active rooms
    pub room_count: u32,
    /// Number of connected users
    pub player_count: u32,
    /// Server uptime in seconds
    pub uptime_secs: u64,
    /// Server version
    pub version: String,
}
