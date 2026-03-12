//! # Retro Server
//!
//! Zero-knowledge encrypted relay server for the Retro anonymous chat application.
//!
//! ## What the server knows
//!
//! - Room IDs and their configuration (expiry timers)
//! - Number of connected clients per room
//! - Encrypted blobs (ciphertext it CANNOT decrypt)
//!
//! ## What the server does NOT know
//!
//! - User identities, IPs, or any metadata (nothing is logged)
//! - Message contents (only sees ciphertext)
//! - Encryption keys (never touches key material)
//! - File contents (only sees encrypted blobs)
//!
//! ## What the server does NOT do
//!
//! - Log anything about users
//! - Store any metadata beyond room config
//! - Moderate content (it can't — everything is encrypted)
//! - Retain data after room closure

mod cleanup;
mod heartbeat;
mod room;
mod state;
mod ws;

use std::net::SocketAddr;

use axum::{extract::State as AxumState, response::IntoResponse, routing::get, Json, Router};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::state::AppState;

// ─── CLI Arguments ──────────────────────────────────────────────────────────

/// Retro Server — Zero-knowledge encrypted relay.
#[derive(Parser, Debug, Clone)]
#[command(name = "retro-server", about = "Retro anonymous chat relay server")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 9300)]
    port: u16,

    /// Server display name (shown in server browser)
    #[arg(long, default_value = "Retro Server")]
    name: String,

    /// Server description
    #[arg(long, default_value = "")]
    description: String,

    /// Maximum number of concurrent users (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    max_players: u32,

    /// Register with the central server registry (opt-in)
    #[arg(long)]
    register: bool,

    /// Registry URL to send heartbeats to
    #[arg(long, default_value = "")]
    registry_url: String,

    /// Public address for clients to connect (ip:port or hostname:port).
    /// Required if --register is used. This is what appears in the server list.
    #[arg(long)]
    public_address: Option<String>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing (server operational logs only — NEVER user data)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    tracing::info!("Retro server '{}' starting...", args.name);

    // Validate --register requires --public-address
    if args.register && args.public_address.is_none() {
        tracing::error!("--register requires --public-address to be set");
        std::process::exit(1);
    }

    // Initialize application state
    let state = AppState::new(args.name.clone(), args.description.clone(), args.max_players);

    // Start the cleanup background task (expiry, overwrite)
    cleanup::spawn_cleanup_task(state.clone());

    // Optionally start heartbeat to registry
    if args.register {
        heartbeat::spawn_heartbeat_task(
            state.clone(),
            args.registry_url.clone(),
            args.public_address.clone().unwrap(),
        );
        tracing::info!(
            "Registry heartbeat enabled → {}",
            args.registry_url
        );
    }

    // Build the router
    let app = Router::new()
        .route("/ws", get(ws::ws_handler))
        .route("/info", get(server_info))
        .with_state(state);

    // Bind and serve
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ─── Server Info Endpoint ───────────────────────────────────────────────────

/// `GET /info` — Returns basic server metadata.
///
/// Clients can query this before connecting to see server name,
/// description, player count, uptime, etc. No sensitive data exposed.
async fn server_info(AxumState(state): AxumState<AppState>) -> impl IntoResponse {
    Json(state.get_server_info())
}
