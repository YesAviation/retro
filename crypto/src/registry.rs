use serde::{Deserialize, Serialize};

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
