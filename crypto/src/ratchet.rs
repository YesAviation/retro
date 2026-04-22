/// Unsure if this is how I want key ratcheting to work. 
// Architectually and efficiency are literal key for this to work

// Right now: New User Joins -> Key Ratches Forward but previous conversational history can't be read
// (Impossible because the previous key is no longer in use (the key that unlocked the previous conversations)

// In terms of security, it makes it impossible for new users to view conversational history prior to their arrival
// In terms of experience, having to constantly explain to users what was being talked about (the context) is annoying. 

use zeroize::Zeroize;

use crate::encryption::KEY_SIZE;
use crate::CryptoError;

/// HKDF info string for the ratchet step.
const RATCHET_INFO: &[u8] = b"retro-ratchet";

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
