//! Key exchange protocol.
//!
//! ## Flow
//!
//! When user A joins a room where user B is already present:
//!
//! ```text
//! A                          Server                         B
//! │                            │                             │
//! │── JoinRoom ──────────────→ │                             │
//! │                            │── MemberJoined(A.pubkeys) →│
//! │                            │                             │
//! │                            │←── KeyExchange(payload) ────│
//! │←── KeyExchange(payload) ──│                             │
//! │                            │                             │
//! │  [A decrypts group key]    │                             │
//! │  [Key ratchets to K(n+1)]  │    [Key ratchets to K(n+1)]│
//! ```
//!
//! ## Defense in Depth
//!
//! The key exchange uses BOTH X25519 ECDH and RSA-4096:
//!
//! 1. B performs X25519 ECDH with A's public key → `shared_ecdh`
//! 2. B encrypts `shared_ecdh` with A's RSA public key → `rsa_wrapped`
//! 3. B encrypts the current group key using `shared_ecdh` (double-wrapped)
//! 4. B signs everything with Ed25519
//! 5. A receives, decrypts RSA, verifies ECDH matches, decrypts group key
//!
//! An attacker must break BOTH X25519 AND RSA-4096 to intercept the group key.

//! Totally unnecessary but why not, right?

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::Zeroize;

use crate::encryption;
use crate::keys::SessionKeys;
use crate::types::{KeyExchangePayload, PublicKeyBundle};
use crate::CryptoError;

/// Perform key exchange as the EXISTING member (sender).
///
/// Given the new member's public keys and the current group key,
/// produce a [`KeyExchangePayload`] that only the new member can decrypt.
pub fn initiate_key_exchange(
    our_keys: &SessionKeys,
    their_public_keys: &PublicKeyBundle,
    group_key: &[u8; 32],
    current_epoch: u64,
) -> Result<KeyExchangePayload, CryptoError> {
    // 1. Decode their X25519 public key from base64
    let their_x25519_bytes = B64
        .decode(&their_public_keys.x25519)
        .map_err(|e| CryptoError::KeyExchange(format!("X25519 decode: {}", e)))?;
    let their_x25519_array: [u8; 32] = their_x25519_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial("X25519 key must be 32 bytes".into()))?;
    let their_x25519 = X25519PublicKey::from(their_x25519_array);

    // 2. Perform X25519 ECDH: shared_secret = our_secret * their_public
    let mut shared_ecdh = our_keys.x25519_secret.diffie_hellman(&their_x25519).to_bytes();

    // 3. RSA-OAEP encrypt the ECDH shared secret with their RSA public key
    //    (defense in depth: attacker must break BOTH X25519 AND RSA-4096)
    let their_rsa_der = B64
        .decode(&their_public_keys.rsa)
        .map_err(|e| CryptoError::KeyExchange(format!("RSA key decode: {}", e)))?;
    let their_rsa = RsaPublicKey::from_pkcs1_der(&their_rsa_der)
        .map_err(|e| CryptoError::Rsa(format!("RSA DER parse: {}", e)))?;
    let rsa_wrapped = their_rsa
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &shared_ecdh)
        .map_err(|e| CryptoError::Rsa(format!("RSA-OAEP encrypt: {}", e)))?;
    let rsa_wrapped_b64 = B64.encode(&rsa_wrapped);

    // 4. Double-wrap encrypt the group key using the ECDH shared secret
    let encrypted_group_key = encryption::encrypt(group_key, &shared_ecdh, current_epoch)?;

    // 5. Ed25519 sign a SHA-256 hash of the payload for authentication.
    //    Using a hash ensures canonical representation regardless of
    //    JSON serialization order or formatting differences.
    let payload_json = serde_json::to_string(&encrypted_group_key)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    let sig_input = format!("{}{}", rsa_wrapped_b64, payload_json);
    let sig_hash = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(sig_input.as_bytes());
        hasher.finalize()
    };
    let signature = our_keys.ed25519_signing.sign(&sig_hash);
    let signature_b64 = B64.encode(signature.to_bytes());

    // 6. Zeroize the shared secret
    shared_ecdh.zeroize();

    Ok(KeyExchangePayload {
        rsa_wrapped_secret: rsa_wrapped_b64,
        encrypted_group_key,
        signature: signature_b64,
    })
}

/// Complete key exchange as the NEW member (receiver).
///
/// Decrypt and verify the [`KeyExchangePayload`] to recover the group key.
pub fn complete_key_exchange(
    our_keys: &SessionKeys,
    sender_public_keys: &PublicKeyBundle,
    payload: &KeyExchangePayload,
) -> Result<[u8; 32], CryptoError> {
    // 1. Verify Ed25519 signature from the sender
    let sender_ed25519_bytes = B64
        .decode(&sender_public_keys.ed25519)
        .map_err(|e| CryptoError::KeyExchange(format!("Ed25519 decode: {}", e)))?;
    let sender_ed25519_array: [u8; 32] = sender_ed25519_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial("Ed25519 key must be 32 bytes".into()))?;
    let sender_verifying = VerifyingKey::from_bytes(&sender_ed25519_array)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("Ed25519: {}", e)))?;

    let payload_json = serde_json::to_string(&payload.encrypted_group_key)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    let sig_input = format!("{}{}", payload.rsa_wrapped_secret, payload_json);
    let sig_hash = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(sig_input.as_bytes());
        hasher.finalize()
    };
    let sig_bytes = B64
        .decode(&payload.signature)
        .map_err(|e| CryptoError::KeyExchange(format!("Signature decode: {}", e)))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| CryptoError::SignatureVerification)?;
    sender_verifying
        .verify(&sig_hash, &signature)
        .map_err(|_| CryptoError::SignatureVerification)?;

    // 2. RSA-OAEP decrypt to recover the ECDH shared secret
    let rsa_wrapped = B64
        .decode(&payload.rsa_wrapped_secret)
        .map_err(|e| CryptoError::KeyExchange(format!("RSA wrapped decode: {}", e)))?;
    let mut shared_ecdh_rsa = our_keys
        .rsa_private
        .decrypt(Oaep::new::<Sha256>(), &rsa_wrapped)
        .map_err(|e| CryptoError::Rsa(format!("RSA-OAEP decrypt: {}", e)))?;

    // 3. Perform X25519 ECDH independently to verify
    let sender_x25519_bytes = B64
        .decode(&sender_public_keys.x25519)
        .map_err(|e| CryptoError::KeyExchange(format!("X25519 decode: {}", e)))?;
    let sender_x25519_array: [u8; 32] = sender_x25519_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial("X25519 key must be 32 bytes".into()))?;
    let sender_x25519 = X25519PublicKey::from(sender_x25519_array);
    let mut shared_ecdh_dh = our_keys.x25519_secret.diffie_hellman(&sender_x25519).to_bytes();

    // 4. Defense in depth: verify both derivations of the shared secret match
    if shared_ecdh_rsa.as_slice() != shared_ecdh_dh.as_slice() {
        shared_ecdh_rsa.zeroize();
        shared_ecdh_dh.zeroize();
        return Err(CryptoError::KeyExchange(
            "ECDH/RSA shared secret mismatch — possible MITM attack".into(),
        ));
    }

    // 5. Decrypt the group key using the shared secret
    let group_key_bytes =
        encryption::decrypt(&payload.encrypted_group_key, &shared_ecdh_dh)?;

    // 6. Zeroize shared secrets
    shared_ecdh_rsa.zeroize();
    shared_ecdh_dh.zeroize();

    // 7. Return the 32-byte group key
    let group_key: [u8; 32] = group_key_bytes
        .try_into()
        .map_err(|_| CryptoError::KeyExchange("Group key must be 32 bytes".into()))?;

    Ok(group_key)
}

/// Derive a per-member DM key from an ECDH shared secret.
///
/// Both parties derive the **same** key because X25519 ECDH is commutative:
/// `our_secret × their_public == their_secret × our_public`
///
/// The raw 32-byte ECDH output is fed through HKDF-SHA256 with a
/// DM-specific info tag to produce a proper 256-bit symmetric key,
/// ensuring domain separation from the group key.
pub fn derive_dm_key(
    our_keys: &SessionKeys,
    their_public_keys: &PublicKeyBundle,
) -> Result<[u8; 32], CryptoError> {
    // Decode their X25519 public key
    let their_x25519_bytes = B64
        .decode(&their_public_keys.x25519)
        .map_err(|e| CryptoError::KeyExchange(format!("X25519 decode: {}", e)))?;
    let their_x25519_array: [u8; 32] = their_x25519_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial("X25519 key must be 32 bytes".into()))?;
    let their_x25519 = X25519PublicKey::from(their_x25519_array);

    // X25519 ECDH
    let shared = our_keys.x25519_secret.diffie_hellman(&their_x25519);

    // HKDF-SHA256 with DM-specific salt and info for domain separation.
    // The salt provides additional cryptographic separation from other
    // HKDF usages (group key derivation, ratchet) that share the same
    // ECDH shared secret.
    let hkdf = hkdf::Hkdf::<Sha256>::new(Some(b"retro-dm-salt-v1"), shared.as_bytes());
    let mut dm_key = [0u8; 32];
    hkdf.expand(b"retro-dm-key", &mut dm_key)
        .map_err(|e| CryptoError::KeyExchange(format!("DM key HKDF: {}", e)))?;

    Ok(dm_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SessionKeys;

    #[test]
    fn test_key_exchange_roundtrip() {
        // Simulate: Alice (existing member) sends group key to Bob (new joiner)
        let alice = SessionKeys::generate().expect("Alice keygen failed");
        let bob = SessionKeys::generate().expect("Bob keygen failed");

        let bob_bundle = bob.public_bundle().expect("Bob bundle failed");

        // The group key that Alice wants to share with Bob
        let mut group_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut group_key);
        let epoch = 5;

        // Alice initiates key exchange
        let payload = initiate_key_exchange(&alice, &bob_bundle, &group_key, epoch)
            .expect("Initiate failed");

        // Bob completes key exchange
        let alice_bundle = alice.public_bundle().expect("Alice bundle failed");
        let recovered_key = complete_key_exchange(&bob, &alice_bundle, &payload)
            .expect("Complete failed");

        assert_eq!(recovered_key, group_key);
    }

    #[test]
    fn test_key_exchange_tampered_signature_fails() {
        let alice = SessionKeys::generate().expect("Alice keygen failed");
        let bob = SessionKeys::generate().expect("Bob keygen failed");
        let bob_bundle = bob.public_bundle().expect("Bob bundle failed");

        let mut group_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut group_key);

        let mut payload = initiate_key_exchange(&alice, &bob_bundle, &group_key, 0)
            .expect("Initiate failed");

        // Tamper with the signature
        let mut sig_bytes = B64.decode(&payload.signature).unwrap();
        sig_bytes[0] ^= 0xFF;
        payload.signature = B64.encode(&sig_bytes);

        let alice_bundle = alice.public_bundle().expect("Alice bundle failed");
        let result = complete_key_exchange(&bob, &alice_bundle, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_exchange_wrong_receiver_fails() {
        let alice = SessionKeys::generate().expect("Alice keygen failed");
        let bob = SessionKeys::generate().expect("Bob keygen failed");
        let eve = SessionKeys::generate().expect("Eve keygen failed");

        let bob_bundle = bob.public_bundle().expect("Bob bundle failed");

        let mut group_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut group_key);

        // Alice sends to Bob
        let payload = initiate_key_exchange(&alice, &bob_bundle, &group_key, 0)
            .expect("Initiate failed");

        // Eve tries to complete (she can't — RSA decryption will fail)
        let alice_bundle = alice.public_bundle().expect("Alice bundle failed");
        let result = complete_key_exchange(&eve, &alice_bundle, &payload);
        assert!(result.is_err());
    }
}
