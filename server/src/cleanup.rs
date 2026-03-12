//! Background cleanup task.
//!
//! Periodically scans rooms for expired messages and files,
//! overwrites them with zeros, then removes them.
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

/// Scan all rooms and clean up expired messages and files.
async fn cleanup_expired(state: &AppState) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // TODO: Phase 3 — Implement expiry cleanup
    // For each room:
    //   1. Check message_expiry_secs config
    //   2. Find messages where (now - timestamp) > expiry
    //   3. Overwrite ciphertext bytes with zeros
    //   4. Remove from messages vec
    //   5. Check file_expiry_secs config
    //   6. Find files where (now - uploaded_at) > expiry
    //   7. Overwrite file ciphertext with zeros
    //   8. Remove from files map
    //   9. If room is empty and has been empty for a while, consider cleanup

    for entry in state.rooms().iter() {
        let room = entry.value();
        let config = &room.config;

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
                    tracing::debug!("Expired + zeroed message in room {}", room.id);
                    false
                } else {
                    true
                }
            });
        }

        // File expiry — overwrite file blob bytes before dropping
        if config.file_expiry_secs > 0 {
            let mut files = room.files.write().await;
            let expired_ids: Vec<String> = files
                .iter()
                .filter_map(|(id, file)| {
                    if now - file.uploaded_at > config.file_expiry_secs {
                        Some(id.clone())
                    } else {
                        None
                    }
                })
                .collect();

            for file_id in expired_ids {
                if let Some(file) = files.get_mut(&file_id) {
                    // SECURITY: Overwrite every byte of the encrypted blob
                    for b in file.ciphertext.iter_mut() {
                        *b = 0u8;
                    }
                    // Also wipe the metadata JSON
                    let meta_bytes = unsafe { file.metadata_json.as_bytes_mut() };
                    for b in meta_bytes.iter_mut() {
                        *b = 0u8;
                    }
                    tracing::debug!("Expired + zeroed file {} in room {}", file_id, room.id);
                }
                files.remove(&file_id);
            }
        }
    }
}
