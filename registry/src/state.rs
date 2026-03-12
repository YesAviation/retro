//! Registry in-memory state.
//!
//! All server entries are stored in a DashMap keyed by their public address.
//! Each entry has a `last_seen` timestamp — if a server misses 3 heartbeat
//! intervals (~90s), it gets delisted.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use retro_crypto::registry::{HeartbeatRequest, ServerListEntry};

/// How often we expect heartbeats (seconds).
const HEARTBEAT_INTERVAL: u64 = 60;

/// How many missed heartbeats before delisting.
const MISSED_HEARTBEATS_LIMIT: u64 = 3;

/// TTL in seconds: if no heartbeat within this window, server is dead.
const SERVER_TTL: u64 = HEARTBEAT_INTERVAL * MISSED_HEARTBEATS_LIMIT;

/// Cleanup task runs every this many seconds.
const CLEANUP_INTERVAL: u64 = 15;

/// Internal representation of a registered server.
#[derive(Debug, Clone)]
struct RegisteredServer {
    /// Display name
    name: String,
    /// Public address (ip:port or hostname:port)
    address: String,
    /// Optional description
    description: String,
    /// Current number of connected users
    player_count: u32,
    /// Maximum capacity (0 = unlimited)
    max_players: u32,
    /// Whether this is an official Retro server
    official: bool,
    /// Unix timestamp of the last heartbeat
    last_seen: u64,
    /// Unix timestamp of when the server first registered
    first_seen: u64,
    /// Server's Retro version string
    version: String,
}

/// Shared registry state.
#[derive(Clone)]
pub struct RegistryState {
    inner: Arc<RegistryStateInner>,
}

struct RegistryStateInner {
    /// Registered servers keyed by address
    servers: DashMap<String, RegisteredServer>,
}

impl RegistryState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RegistryStateInner {
                servers: DashMap::new(),
            }),
        }
    }

    /// Insert or update a server entry from a heartbeat.
    pub fn upsert_server(&self, req: HeartbeatRequest) {
        let now = now_secs();

        self.inner
            .servers
            .entry(req.address.clone())
            .and_modify(|existing| {
                existing.name = req.name.clone();
                existing.description = req.description.clone().unwrap_or_default();
                existing.player_count = req.player_count;
                existing.max_players = req.max_players.unwrap_or(0);
                existing.version = req.version.clone().unwrap_or_default();
                existing.last_seen = now;
            })
            .or_insert_with(|| {
                tracing::info!("New server registered: {} ({})", req.name, req.address);
                RegisteredServer {
                    name: req.name,
                    address: req.address,
                    description: req.description.unwrap_or_default(),
                    player_count: req.player_count,
                    max_players: req.max_players.unwrap_or(0),
                    official: false, // Only set via config, not via heartbeat
                    last_seen: now,
                    first_seen: now,
                    version: req.version.unwrap_or_default(),
                }
            });
    }

    /// Get the server list for clients.
    ///
    /// Official servers are sorted to the top, then by player count descending.
    pub fn get_server_list(&self, official_only: bool) -> Vec<ServerListEntry> {
        let now = now_secs();

        let mut list: Vec<ServerListEntry> = self
            .inner
            .servers
            .iter()
            .filter(|entry| {
                let server = entry.value();
                let alive = (now - server.last_seen) < SERVER_TTL;
                if official_only {
                    alive && server.official
                } else {
                    alive
                }
            })
            .map(|entry| {
                let server = entry.value();
                ServerListEntry {
                    name: server.name.clone(),
                    address: server.address.clone(),
                    description: server.description.clone(),
                    player_count: server.player_count,
                    max_players: server.max_players,
                    official: server.official,
                    version: server.version.clone(),
                }
            })
            .collect();

        // Sort: official first, then by player count descending
        list.sort_by(|a, b| {
            b.official
                .cmp(&a.official)
                .then_with(|| b.player_count.cmp(&a.player_count))
        });

        list
    }

    /// Number of currently tracked servers.
    pub fn server_count(&self) -> usize {
        self.inner.servers.len()
    }

    /// Remove servers that haven't sent a heartbeat within the TTL window.
    fn cleanup_dead_servers(&self) {
        let now = now_secs();
        self.inner.servers.retain(|_addr, server| {
            let alive = (now - server.last_seen) < SERVER_TTL;
            if !alive {
                tracing::info!(
                    "Delisting dead server: {} ({}), last seen {}s ago",
                    server.name,
                    server.address,
                    now - server.last_seen
                );
            }
            alive
        });
    }
}

/// Spawn the cleanup background task that delists dead servers.
pub fn spawn_cleanup_task(state: RegistryState) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(CLEANUP_INTERVAL));

        loop {
            interval.tick().await;
            state.cleanup_dead_servers();
        }
    });
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
