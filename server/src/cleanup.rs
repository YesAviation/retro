//! Background cleanup task.
//!
//! Periodically scans rooms for expired messages,
//! overwrites them with zeros, then removes them.
//!
//! Also destroys empty rooms that have no members —
//! rooms should not persist after all participants leave.
//!
//! ## Overwrite Policy
//!
//! We don't just `drop` expired data — we **overwrite** the memory with
//! zeros before deallocating. This ensures that even if the allocator
//! reuses the memory, no ciphertext remnants remain.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::AppState;

/// Cleanup interval in seconds.
const CLEANUP_INTERVAL_SECS: u64 = 30;

/// Spawn the background cleanup task.
pub fn spawn_cleanup_task(state: AppState) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));

        loop {
            interval.tick().await;
            cleanup_expired(&state).await;
        }
    });
}

/// Scan all rooms and clean up expired messages + empty rooms.
async fn cleanup_expired(state: &AppState) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Collect room IDs to destroy (empty rooms)
    let mut rooms_to_destroy: Vec<String> = Vec::new();

    for entry in state.rooms().iter() {
        let room = entry.value();
        let config = &room.config;

        // Check if room is empty — auto-destroy
        if room.is_empty().await {
            rooms_to_destroy.push(room.id.clone());
            continue;
        }

        // Message expiry — overwrite ciphertext bytes before dropping
        if config.message_expiry_secs > 0 {
            let mut messages = room.messages.write().await;
            messages.retain_mut(|msg| {
                if now - msg.timestamp > config.message_expiry_secs {
                    // SECURITY: Zero out the ciphertext bytes before drop
                    // so the allocator cannot leak remnants on reuse.
                    // SAFETY: We're writing zeros to owned Vec bytes.
                    let bytes = unsafe { msg.ciphertext.as_bytes_mut() };
                    for b in bytes.iter_mut() {
                        *b = 0u8;
                    }
                    tracing::debug!("Expired + zeroed message in room");
                    false
                } else {
                    true
                }
            });
        }
    }

    // Destroy empty rooms outside of the iterator
    for room_id in rooms_to_destroy {
        state.destroy_room(&room_id);
        tracing::debug!("Auto-destroyed empty room");
    }
}
