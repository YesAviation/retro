//! Shared types for the Retro server registry / discovery system.
//!
//! These types are used by:
//! - **retro-registry** — the central server list service
//! - **retro-server** — sends heartbeats to register itself
//! - **retro-client** — fetches and displays the server list

use serde::{Deserialize, Serialize};

// ─── Heartbeat (Server → Registry) ─────────────────────────────────────────

/// Heartbeat payload sent from a Retro server to the registry.
///
/// Servers send this every ~30s to stay listed. If heartbeats stop,
/// the registry automatically delists the server after ~90s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    /// Display name of the server
    pub name: String,
    /// Public address for clients to connect (ip:port or hostname:port)
    pub address: String,
    /// Optional human-readable description
    pub description: Option<String>,
    /// Current number of connected users
    pub player_count: u32,
    /// Maximum capacity (0 or None = unlimited)
    pub max_players: Option<u32>,
    /// Server's Retro version string
    pub version: Option<String>,
}

// ─── Server List (Registry → Client) ────────────────────────────────────────

/// A single entry in the server list returned to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerListEntry {
    /// Display name
    pub name: String,
    /// Address to connect to (ip:port or hostname:port)
    pub address: String,
    /// Description
    pub description: String,
    /// Current player count
    pub player_count: u32,
    /// Max capacity (0 = unlimited)
    pub max_players: u32,
    /// Whether this is an official Retro server
    pub official: bool,
    /// Server version
    pub version: String,
}

/// Response from the GET /api/servers endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerListResponse {
    pub servers: Vec<ServerListEntry>,
    pub count: usize,
}

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
