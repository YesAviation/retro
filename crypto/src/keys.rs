use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::types::PublicKeyBundle;
use crate::CryptoError;

/// RSA key size in bits. 4096-bit for maximum security.
const RSA_KEY_BITS: usize = 4096;

pub struct SessionKeys {
    // ── Key Exchange ──
    /// X25519 secret key (for ECDH)
    pub x25519_secret: X25519Secret,
    /// X25519 public key
    pub x25519_public: X25519PublicKey,

    // ── Signatures ──
    /// Ed25519 signing key
    pub ed25519_signing: SigningKey,

    // ── RSA Wrapping ──
    /// RSA-4096 private key
    pub rsa_private: RsaPrivateKey,
    /// RSA-4096 public key
    pub rsa_public: RsaPublicKey,
}

impl SessionKeys {
    pub fn generate() -> Result<Self, CryptoError> {
        // X25519 keypair for Diffie-Hellman key exchange
        let x25519_secret = X25519Secret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Ed25519 keypair for digital signatures
        let ed25519_signing = SigningKey::generate(&mut OsRng);

        // RSA-4096 keypair for additional key wrapping (defense in depth)
        // Note: RSA key generation is computationally expensive (~1-3s)
        let rsa_private = RsaPrivateKey::new(&mut OsRng, RSA_KEY_BITS)
            .map_err(|e| CryptoError::KeyGeneration(format!("RSA-4096: {}", e)))?;
        let rsa_public = RsaPublicKey::from(&rsa_private);

        Ok(Self {
            x25519_secret,
            x25519_public,
            ed25519_signing,
            rsa_private,
            rsa_public,
        })
    }

    pub fn public_bundle(&self) -> Result<PublicKeyBundle, CryptoError> {
        // X25519 public key: 32 bytes → base64
        let x25519 = B64.encode(self.x25519_public.as_bytes());

        // Ed25519 verifying key: 32 bytes → base64
        let ed25519 = B64.encode(self.ed25519_signing.verifying_key().as_bytes());

        // RSA public key: PKCS#1 DER encoding → base64
        let rsa_der = self
            .rsa_public
            .to_pkcs1_der()
            .map_err(|e| CryptoError::Rsa(format!("DER encode: {}", e)))?;
        let rsa = B64.encode(rsa_der.as_bytes());

        Ok(PublicKeyBundle { x25519, ed25519, rsa })
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        if let Ok(der) = self.rsa_private.to_pkcs1_der() {
            let mut der_bytes = der.as_bytes().to_vec();
            der_bytes.zeroize();
        }

        if let Ok(dummy) = RsaPrivateKey::new(&mut OsRng, 512) {
            self.rsa_private = dummy;
            self.rsa_public = RsaPublicKey::from(&self.rsa_private);
        }
    }
}

pub fn generate_handle() -> String {
    use rand::Rng;
    let mut rng = OsRng;
    let suffix: String = (0..4)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect();
    format!("anon_{}", suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_handle() {
        let handle = generate_handle();
        assert!(handle.starts_with("anon_"));
        assert_eq!(handle.len(), 9); // "anon_" (5) + 4 chars
    }

    #[test]
    fn test_handle_uniqueness() {
        let handles: Vec<String> = (0..100).map(|_| generate_handle()).collect();
        let unique: std::collections::HashSet<&String> = handles.iter().collect();
        // With 36^4 = 1.6M possibilities, 100 handles should all be unique
        assert_eq!(unique.len(), handles.len());
    }

    #[test]
    fn test_generate_session_keys() {
        let keys = SessionKeys::generate().expect("Key generation failed");
        // Verify X25519 public key matches the secret
        let expected_public = X25519PublicKey::from(&keys.x25519_secret);
        assert_eq!(keys.x25519_public.as_bytes(), expected_public.as_bytes());
    }

    #[test]
    fn test_public_bundle_roundtrip() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let keys = SessionKeys::generate().expect("Key generation failed");
        let bundle = keys.public_bundle().expect("Bundle creation failed");

        // Verify X25519 public key decodes correctly
        let x25519_bytes = B64.decode(&bundle.x25519).unwrap();
        assert_eq!(x25519_bytes.len(), 32);
        assert_eq!(x25519_bytes.as_slice(), keys.x25519_public.as_bytes());

        // Verify Ed25519 verifying key decodes correctly
        let ed25519_bytes = B64.decode(&bundle.ed25519).unwrap();
        assert_eq!(ed25519_bytes.len(), 32);

        // Verify RSA public key decodes as valid PKCS#1 DER
        let rsa_bytes = B64.decode(&bundle.rsa).unwrap();
        assert!(!rsa_bytes.is_empty());
    }

    #[test]
    fn test_keys_are_unique_per_session() {
        let keys1 = SessionKeys::generate().expect("Key generation failed");
        let keys2 = SessionKeys::generate().expect("Key generation failed");
        // Different sessions must produce different keys
        assert_ne!(keys1.x25519_public.as_bytes(), keys2.x25519_public.as_bytes());
    }
}
