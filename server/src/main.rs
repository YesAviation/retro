// Server Main
// Basically, you send a message. Message gets encrypted.
// Server doesn't have capability or knowledge to decrypt. 
// Server is just the "mailman".
// Server delivers message, client decrpyts.
// Clients use E2EE (End2End-Encryption)
// Keys get ratcheted every time someone joins a chatroom
// When someone joins a chatroom, previous messages can't been seen (key ratcheted forwards). 
// When rooms go abandoned, chat rooms get overwritten and destroyed into nothing
// When a room is forcefully closed, chat rooms get overwritten and destroyed into nothing

// Recommended running on hardware w/physical hard drives (HDDs) and not SSDs. 
// HDDs can effectively be overwritten using 1's and 0's. SSDs cannot (at least not effectively)

mod cleanup;
mod room;
mod state;
mod ws;

use std::net::SocketAddr;

use axum::{extract::State as AxumState, response::IntoResponse, routing::get, Json, Router};
use clap::Parser;
use tokio::signal;
use tracing_subscriber::EnvFilter;

use crate::state::AppState;

// ─── CLI Arguments ──────────────────────────────────────────────────────────

/// Retro Server — Zero-knowledge encrypted relay.
#[derive(Parser, Debug, Clone)]
#[command(name = "retro-server", about = "Retro anonymous chat relay server")]
struct Args {
    /// Hardcoded port; Must decide if I really want this to be configurable
    #[arg(short, long, default_value_t = 9300)]
    port: u16,

    /// Server display name
    #[arg(long, default_value = "Retro Server")]
    name: String,

    /// Server description
    #[arg(long, default_value = "")]
    description: String,

    // Server Admin Configurable
    /// Maximum number of concurrent users (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    max_players: u32,

    // Server Admin Configurable
    /// Maximum number of rooms (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    max_rooms: u32,

    // Server Admin Configurable
    /// Maximum message size in bytes (default: 64 KB)
    #[arg(long, default_value_t = 65536)]
    max_message_size: usize,
}

#[tokio::main]
async fn main() {
    // TODO: Remove tracing. 
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

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    // Graceful shutdown on SIGTERM / SIGINT / Ctrl+C
    let serve = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal());

    if let Err(e) = serve.await {
        tracing::error!("Server error: {}", e);
        std::process::exit(1);
    }

    tracing::info!("Server shut down gracefully");
}

/// Wait for a shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { tracing::info!("Received Ctrl+C, shutting down..."); }
        _ = terminate => { tracing::info!("Received SIGTERM, shutting down..."); }
    }
}

// Wasn't this a part of heartbeat, which I removed? Oops, this won't do anything. 
// Or at least, it shouldn't. 
async fn server_info(AxumState(state): AxumState<AppState>) -> impl IntoResponse {
    Json(state.get_server_info())
}
