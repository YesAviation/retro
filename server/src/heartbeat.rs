//! Heartbeat task — registers this server with the central registry.
//!
//! When `--register` is passed on the CLI, this task sends a heartbeat
//! every 30 seconds to the configured registry URL. If the task stops
//! (server shuts down), the registry will automatically delist it after ~90s.
//!
//! This is completely **opt-in**. Servers that don't pass `--register`
//! never contact the registry and are only reachable via direct connect.

use crate::state::AppState;
use retro_crypto::registry::HeartbeatRequest;

/// How often to send heartbeats to the registry (seconds).
const HEARTBEAT_INTERVAL: u64 = 30;

/// Spawn the background heartbeat task.
pub fn spawn_heartbeat_task(state: AppState, registry_url: String, public_address: String) {
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let endpoint = format!("{}/api/heartbeat", registry_url.trim_end_matches('/'));

        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL));

        tracing::info!(
            "Heartbeat task started → {} as '{}'",
            endpoint,
            state.name()
        );

        loop {
            interval.tick().await;

            let payload = HeartbeatRequest {
                name: state.name().to_string(),
                address: public_address.clone(),
                description: Some(state.description().to_string()),
                player_count: state.player_count(),
                max_players: Some(state.max_players()),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            };

            match client.post(&endpoint).json(&payload).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        tracing::warn!(
                            "Registry heartbeat returned {}: {}",
                            resp.status(),
                            resp.text().await.unwrap_or_default()
                        );
                    } else {
                        tracing::debug!("Heartbeat sent successfully");
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to send heartbeat: {}", e);
                }
            }
        }
    });
}
