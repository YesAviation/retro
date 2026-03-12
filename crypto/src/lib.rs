//! # Retro Crypto
//!
//! Core cryptographic library for the Retro anonymous chat application.
//!
//! ## Design Principles
//!
//! 1. **Ephemeral by default**: All keys are generated per-session and destroyed on disconnect
//! 2. **Double-wrapped encryption**: Every message passes through XChaCha20-Poly1305 (inner)
//!    then AES-256-GCM (outer) — two independent ciphers from different algorithm families
//! 3. **Defense in depth**: Key exchange uses both X25519 ECDH and RSA-4096 OAEP wrapping
//! 4. **Forward secrecy**: Group key ratchets on every membership change
//! 5. **Zeroization**: All secret material is securely wiped from memory on drop
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                   Session Start                  │
//! │  Generate: X25519 + Ed25519 + RSA-4096 keypairs │
//! └──────────────────────┬──────────────────────────┘
//! │
//! ┌──────────────────────▼──────────────────────────┐
//! │               Key Exchange (join room)           │
//! │  X25519 ECDH → shared_secret                    │
//! │  RSA-OAEP wrap shared_secret (defense in depth) │
//! │  Derive group key via shared_secret              │
//! └──────────────────────┬──────────────────────────┘
//! │
//! ┌──────────────────────▼──────────────────────────┐
//! │              Message Encryption                  │
//! │  HKDF(group_key) → K_inner + K_outer            │
//! │  plaintext → XChaCha20-Poly1305(K_inner)        │
//! │           → AES-256-GCM(K_outer)                │
//! │           → ciphertext (double-wrapped)          │
//! └──────────────────────┬──────────────────────────┘
//! │
//! ┌──────────────────────▼──────────────────────────┐
//! │          Membership Change (ratchet)             │
//! │  K(n+1) = HKDF(K(n), epoch)                     │
//! │  K(n) is zeroized immediately                    │
//! └──────────────────────┬──────────────────────────┘
//! │
//! ┌──────────────────────▼──────────────────────────┐
//! │               Session End                        │
//! │  All keys zeroized. Cryptographic death.         │
//! └─────────────────────────────────────────────────┘
//! ```

pub mod types;
pub mod keys;
pub mod encryption;
pub mod exchange;
pub mod ratchet;
pub mod registry;

pub use types::*;
pub use keys::SessionKeys;
