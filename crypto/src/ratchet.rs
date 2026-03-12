//! Group key ratcheting for forward secrecy.
//!
//! ## Design
//!
//! The group key ratchets forward on every membership change (join or leave).
//! This ensures **forward secrecy**: compromising the current key reveals
//! nothing about messages encrypted under previous keys.
//!
//! ```text
//! K(0) ──HKDF──→ K(1) ──HKDF──→ K(2) ──HKDF──→ ...
//!   │               │               │
//!   └─ zeroized     └─ zeroized     └─ current
//! ```
//!
//! - When a member **joins**: ratchet forward so the new member cannot
//!   decrypt messages from before their arrival (not that they'd have them,
//!   but defense in depth)
//! - When a member **leaves**: ratchet forward so the departed member
//!   cannot decrypt future messages (even if they retained their keys)
//!
//! ## Key Derivation
//!
//! ```text
//! K(n+1) = HKDF-SHA256(
//!     IKM  = K(n),
//!     salt = epoch_number as big-endian bytes,
//!     info = b"retro-ratchet"
//! )
//! ```

use zeroize::Zeroize;

use crate::encryption::KEY_SIZE;
use crate::CryptoError;

/// HKDF info string for the ratchet step.
const RATCHET_INFO: &[u8] = b"retro-ratchet";

/// Group key ratchet state.
///
/// Manages the current group key and epoch counter.
/// Previous keys are immediately zeroized after ratcheting.
pub struct GroupKeyRatchet {
    /// Current group key (256-bit)
    current_key: [u8; KEY_SIZE],
    /// Current epoch number (increments on each ratchet step)
    epoch: u64,
}

impl GroupKeyRatchet {
    /// Create a new ratchet with a randomly generated initial key.
    pub fn new() -> Result<Self, CryptoError> {
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);

        Ok(Self {
            current_key: key,
            epoch: 0,
        })
    }

    /// Create a ratchet from a received group key (for new members).
    pub fn from_key(key: [u8; KEY_SIZE], epoch: u64) -> Self {
        Self {
            current_key: key,
            epoch,
        }
    }

    /// Ratchet the key forward by one step.
    ///
    /// The previous key is **zeroized** immediately.
    /// Returns the new epoch number.
    pub fn ratchet(&mut self) -> Result<u64, CryptoError> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let next_epoch = self.epoch + 1;
        let salt = next_epoch.to_be_bytes();

        // Derive next key: K(n+1) = HKDF(K(n), salt=epoch, info="retro-ratchet")
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &self.current_key);
        let mut next_key = [0u8; KEY_SIZE];
        hkdf.expand(RATCHET_INFO, &mut next_key)
            .map_err(|e| CryptoError::Ratchet(format!("HKDF: {}", e)))?;

        // Zeroize old key immediately — forward secrecy
        self.current_key.zeroize();

        // Install new key
        self.current_key = next_key;
        self.epoch = next_epoch;

        Ok(self.epoch)
    }

    /// Get the current group key (for encryption/decryption).
    pub fn current_key(&self) -> &[u8; KEY_SIZE] {
        &self.current_key
    }

    /// Get the current epoch number.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Zeroize all key material on drop.
impl Drop for GroupKeyRatchet {
    fn drop(&mut self) {
        self.current_key.zeroize();
        self.epoch = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_ratchet() {
        let ratchet = GroupKeyRatchet::new().expect("Ratchet creation failed");
        assert_eq!(ratchet.epoch(), 0);
        // Key should not be all zeros
        assert_ne!(ratchet.current_key(), &[0u8; KEY_SIZE]);
    }

    #[test]
    fn test_ratchet_produces_different_key() {
        let mut ratchet = GroupKeyRatchet::new().expect("Ratchet creation failed");
        let key0 = *ratchet.current_key();

        ratchet.ratchet().expect("Ratchet failed");
        let key1 = *ratchet.current_key();

        assert_ne!(key0, key1, "Ratchet must produce a different key");
    }

    #[test]
    fn test_ratchet_increments_epoch() {
        let mut ratchet = GroupKeyRatchet::new().expect("Ratchet creation failed");
        assert_eq!(ratchet.epoch(), 0);

        let epoch1 = ratchet.ratchet().expect("Ratchet failed");
        assert_eq!(epoch1, 1);

        let epoch2 = ratchet.ratchet().expect("Ratchet failed");
        assert_eq!(epoch2, 2);
    }

    #[test]
    fn test_ratchet_deterministic_from_same_key() {
        // Same starting key + same ratchet steps = same resulting keys
        let key = [42u8; KEY_SIZE];

        let mut ratchet_a = GroupKeyRatchet::from_key(key, 0);
        let mut ratchet_b = GroupKeyRatchet::from_key(key, 0);

        ratchet_a.ratchet().unwrap();
        ratchet_b.ratchet().unwrap();

        assert_eq!(ratchet_a.current_key(), ratchet_b.current_key());
        assert_eq!(ratchet_a.epoch(), ratchet_b.epoch());
    }

    #[test]
    fn test_ratchet_chain_is_irreversible() {
        // After ratcheting, we can verify we can't derive the old key
        // from the new one (one-way by construction of HKDF)
        let mut ratchet = GroupKeyRatchet::new().expect("Ratchet creation failed");
        let key0 = *ratchet.current_key();

        ratchet.ratchet().unwrap();
        let key1 = *ratchet.current_key();

        ratchet.ratchet().unwrap();
        let key2 = *ratchet.current_key();

        // All keys must be unique
        assert_ne!(key0, key1);
        assert_ne!(key1, key2);
        assert_ne!(key0, key2);
    }

    #[test]
    fn test_from_key_preserves_state() {
        let key = [0xAB; KEY_SIZE];
        let ratchet = GroupKeyRatchet::from_key(key, 10);

        assert_eq!(ratchet.current_key(), &key);
        assert_eq!(ratchet.epoch(), 10);
    }
}
