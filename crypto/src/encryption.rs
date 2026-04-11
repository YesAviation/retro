//! Double-wrapped symmetric encryption.
//!
//! ## Scheme
//!
//! Every message is encrypted twice with independent keys derived from the
//! group key via HKDF-SHA256:
//!
//! ```text
//! group_key ──┬── HKDF("retro-inner") ──→ K_inner (XChaCha20-Poly1305)
//!             └── HKDF("retro-outer") ──→ K_outer (AES-256-GCM)
//!
//! plaintext
//!   → XChaCha20-Poly1305(K_inner, nonce_inner)  // 24-byte nonce
//!   → AES-256-GCM(K_outer, nonce_outer)          // 12-byte nonce
//!   → double-wrapped ciphertext
//! ```
//!
//! ## Why double-wrap?
//!
//! - **Algorithm diversity**: If a vulnerability is found in one cipher,
//!   the other still protects the data
//! - **Side-channel resistance**: Different algorithm families have different
//!   side-channel profiles, making attacks significantly harder
//! - **Defense in depth**: An attacker must break BOTH ciphers to read messages

use aes_gcm::Aes256Gcm;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::types::EncryptedPayload;
use crate::CryptoError;

/// Symmetric key size in bytes (256-bit).
pub const KEY_SIZE: usize = 32;

/// HKDF info string for deriving the inner key (XChaCha20-Poly1305).
const HKDF_INFO_INNER: &[u8] = b"retro-inner-xchacha20poly1305";

/// HKDF info string for deriving the outer key (AES-256-GCM).
const HKDF_INFO_OUTER: &[u8] = b"retro-outer-aes256gcm";

/// Derive inner and outer subkeys from a group key using HKDF-SHA256.
///
/// Returns `(inner_key, outer_key)`, each 32 bytes.
pub fn derive_subkeys(
    group_key: &[u8; KEY_SIZE],
    epoch: u64,
) -> Result<([u8; KEY_SIZE], [u8; KEY_SIZE]), CryptoError> {
    let salt = epoch.to_be_bytes();

    // Derive inner key (XChaCha20-Poly1305)
    let hkdf_inner = Hkdf::<Sha256>::new(Some(&salt), group_key);
    let mut inner_key = [0u8; KEY_SIZE];
    hkdf_inner
        .expand(HKDF_INFO_INNER, &mut inner_key)
        .map_err(|e| CryptoError::Encryption(format!("HKDF inner: {}", e)))?;

    // Derive outer key (AES-256-GCM)
    let hkdf_outer = Hkdf::<Sha256>::new(Some(&salt), group_key);
    let mut outer_key = [0u8; KEY_SIZE];
    hkdf_outer
        .expand(HKDF_INFO_OUTER, &mut outer_key)
        .map_err(|e| CryptoError::Encryption(format!("HKDF outer: {}", e)))?;

    Ok((inner_key, outer_key))
}

/// Encrypt plaintext with double-wrapped encryption.
///
/// 1. Derive subkeys from group key
/// 2. Encrypt with XChaCha20-Poly1305 (inner layer)
/// 3. Encrypt the result with AES-256-GCM (outer layer)
/// 4. Return the double-wrapped payload
pub fn encrypt(
    plaintext: &[u8],
    group_key: &[u8; KEY_SIZE],
    epoch: u64,
) -> Result<EncryptedPayload, CryptoError> {
    let (mut inner_key, mut outer_key) = derive_subkeys(group_key, epoch)?;

    // ── Inner layer: XChaCha20-Poly1305 (24-byte nonce) ──
    let inner_cipher = XChaCha20Poly1305::new(
        chacha20poly1305::Key::from_slice(&inner_key),
    );
    let mut inner_nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut inner_nonce_bytes);
    let inner_nonce = chacha20poly1305::XNonce::from_slice(&inner_nonce_bytes);
    let inner_ciphertext = inner_cipher
        .encrypt(inner_nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(format!("XChaCha20-Poly1305: {}", e)))?;

    // ── Outer layer: AES-256-GCM (12-byte nonce) ──
    let outer_cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&outer_key));
    let mut outer_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut outer_nonce_bytes);
    let outer_nonce = aes_gcm::Nonce::from_slice(&outer_nonce_bytes);
    let outer_ciphertext = outer_cipher
        .encrypt(outer_nonce, inner_ciphertext.as_slice())
        .map_err(|e| CryptoError::Encryption(format!("AES-256-GCM: {}", e)))?;

    // ── Zeroize key material ──
    inner_key.zeroize();
    outer_key.zeroize();

    Ok(EncryptedPayload {
        outer_nonce: B64.encode(outer_nonce_bytes),
        inner_nonce: B64.encode(inner_nonce_bytes),
        ciphertext: B64.encode(outer_ciphertext),
        epoch,
    })
}

/// Decrypt a double-wrapped payload.
///
/// 1. Derive subkeys from group key
/// 2. Decrypt outer layer (AES-256-GCM)
/// 3. Decrypt inner layer (XChaCha20-Poly1305)
/// 4. Return plaintext
pub fn decrypt(
    payload: &EncryptedPayload,
    group_key: &[u8; KEY_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    let (mut inner_key, mut outer_key) = derive_subkeys(group_key, payload.epoch)?;

    // Base64-decode nonces and ciphertext
    let outer_nonce_bytes = B64
        .decode(&payload.outer_nonce)
        .map_err(|e| CryptoError::Decryption(format!("outer nonce base64: {}", e)))?;
    let inner_nonce_bytes = B64
        .decode(&payload.inner_nonce)
        .map_err(|e| CryptoError::Decryption(format!("inner nonce base64: {}", e)))?;
    let ciphertext = B64
        .decode(&payload.ciphertext)
        .map_err(|e| CryptoError::Decryption(format!("ciphertext base64: {}", e)))?;

    // ── Outer layer: AES-256-GCM decrypt ──
    let outer_cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&outer_key));
    let outer_nonce = aes_gcm::Nonce::from_slice(&outer_nonce_bytes);
    let inner_ciphertext = outer_cipher
        .decrypt(outer_nonce, ciphertext.as_slice())
        .map_err(|e| CryptoError::Decryption(format!("AES-256-GCM: {}", e)))?;

    // ── Inner layer: XChaCha20-Poly1305 decrypt ──
    let inner_cipher = XChaCha20Poly1305::new(
        chacha20poly1305::Key::from_slice(&inner_key),
    );
    let inner_nonce = chacha20poly1305::XNonce::from_slice(&inner_nonce_bytes);
    let plaintext = inner_cipher
        .decrypt(inner_nonce, inner_ciphertext.as_slice())
        .map_err(|e| CryptoError::Decryption(format!("XChaCha20-Poly1305: {}", e)))?;

    // ── Zeroize key material ──
    inner_key.zeroize();
    outer_key.zeroize();

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let epoch = 42;

        let payload = encrypt(plaintext, &key, epoch).expect("Encrypt failed");
        let decrypted = decrypt(&payload, &key).expect("Decrypt failed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);

        let payload = encrypt(b"", &key, 0).expect("Encrypt failed");
        let decrypted = decrypt(&payload, &key).expect("Decrypt failed");

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_large() {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        let plaintext = vec![0xABu8; 1024 * 64]; // 64 KB

        let payload = encrypt(&plaintext, &key, 1).expect("Encrypt failed");
        let decrypted = decrypt(&payload, &key).expect("Decrypt failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut key1 = [0u8; KEY_SIZE];
        let mut key2 = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key1);
        OsRng.fill_bytes(&mut key2);

        let payload = encrypt(b"secret", &key1, 0).expect("Encrypt failed");
        let result = decrypt(&payload, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);

        let mut payload = encrypt(b"secret", &key, 0).expect("Encrypt failed");
        // Tamper with the ciphertext
        let mut ct_bytes = B64.decode(&payload.ciphertext).unwrap();
        if let Some(byte) = ct_bytes.last_mut() {
            *byte ^= 0xFF;
        }
        payload.ciphertext = B64.encode(&ct_bytes);

        let result = decrypt(&payload, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_subkeys_are_different() {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);

        let (inner, outer) = derive_subkeys(&key, 0).expect("Derive failed");
        // Inner and outer keys must be different (different HKDF info strings)
        assert_ne!(inner, outer);
    }

    #[test]
    fn test_different_epochs_produce_different_subkeys() {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);

        let (inner1, outer1) = derive_subkeys(&key, 0).expect("Derive failed");
        let (inner2, outer2) = derive_subkeys(&key, 1).expect("Derive failed");

        assert_ne!(inner1, inner2);
        assert_ne!(outer1, outer2);
    }
}
