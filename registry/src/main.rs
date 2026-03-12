//! # Retro Registry
//!
//! Central server discovery service for the Retro network.
//!
//! This is the "server list" that self-hosters can optionally
//! register with so clients can browse available servers.
//!
//! ## Endpoints
//!
//! - `POST /api/heartbeat`  — Servers call this every ~30s to stay listed
//! - `GET  /api/servers`    — Clients fetch the full server list
//!
//! ## Design Principles
//!
//! - **Opt-in only** — Servers are never listed without explicitly registering
//! - **No accounts** — Registration requires only a simple API key
//! - **Stateless** — All data is in-memory with TTL-based expiry
//! - **Minimal metadata** — Only what clients need to connect (name, address, player count)
//! - **No user data** — The registry knows nothing about who uses which server

mod state;

use std::net::SocketAddr;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

use retro_crypto::registry::HeartbeatRequest;

use crate::state::RegistryState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Retro Registry starting...");

    let state = RegistryState::new();

    // Spawn the cleanup task (delist dead servers)
    state::spawn_cleanup_task(state.clone());

    let app = Router::new()
        .route("/api/heartbeat", post(heartbeat))
        .route("/api/servers", get(server_list))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 9301));
    tracing::info!("Registry listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ─── Heartbeat ──────────────────────────────────────────────────────────────

/// Receive a heartbeat from a self-hosted server.
///
/// The server sends its metadata periodically. If we stop receiving
/// heartbeats, the server is automatically delisted after the TTL.
async fn heartbeat(
    State(state): State<RegistryState>,
    Json(payload): Json<HeartbeatRequest>,
) -> impl IntoResponse {
    // Basic validation
    if payload.name.is_empty() || payload.address.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "name and address are required" })),
        );
    }

    if payload.name.len() > 64 || payload.address.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "name or address too long" })),
        );
    }

    state.upsert_server(payload);

    tracing::debug!("Heartbeat received, total servers: {}", state.server_count());

    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "ok" })),
    )
}

// ─── Server List ────────────────────────────────────────────────────────────

/// Query parameters for the server list endpoint.
#[derive(Debug, Deserialize)]
struct ServerListQuery {
    /// If true, only return servers flagged as official.
    official_only: Option<bool>,
}

/// Return the current list of registered servers.
///
/// Official servers are always pinned to the top.
async fn server_list(
    State(state): State<RegistryState>,
    Query(query): Query<ServerListQuery>,
) -> impl IntoResponse {
    let official_only = query.official_only.unwrap_or(false);
    let servers = state.get_server_list(official_only);

    Json(serde_json::json!({
        "servers": servers,
        "count": servers.len(),
    }))
}
