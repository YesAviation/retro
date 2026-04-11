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
//!
//! ## What the server does NOT do
//!
//! - Log anything about users
//! - Store any metadata beyond room config
//! - Moderate content (it can't — everything is encrypted)
//! - Retain data after room closure

mod cleanup;
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

    /// Server display name
    #[arg(long, default_value = "Retro Server")]
    name: String,

    /// Server description
    #[arg(long, default_value = "")]
    description: String,

    /// Maximum number of concurrent users (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    max_players: u32,

    /// Maximum number of rooms (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    max_rooms: u32,

    /// Maximum message size in bytes (default: 64 KB)
    #[arg(long, default_value_t = 65536)]
    max_message_size: usize,
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

    // Initialize application state
    let state = AppState::new(
        args.name.clone(),
        args.description.clone(),
        args.max_players,
        args.max_rooms,
        args.max_message_size,
    );

    // Start background tasks
    cleanup::spawn_cleanup_task(state.clone());

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
