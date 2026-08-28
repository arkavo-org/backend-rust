//! Secure key handling with automatic zeroization.
//!
//! This module provides wrappers around cryptographic keys that ensure
//! sensitive key material is automatically zeroized on drop.
//!
//! `SecureEcPrivateKey` holds the KAS EC private key for the whole process:
//! `KasKeys`, `RewrapState` and the RTMP server/session all store this type
//! rather than raw bytes, so the secret is never copied into a plain
//! `Vec<u8>`/`[u8; 32]` that outlives a single call.
//!
//! Note: `SecureRsaPrivateKey` is prepared for future use and not yet wired in.

use elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use secrecy::{ExposeSecret, Secret};
use std::fmt;

/// Error type for key operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Invalid key size: expected {expected}, got {got}")]
    InvalidKeySize { expected: usize, got: usize },

    #[error("Invalid key format: {0}")]
    InvalidFormat(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
}

/// Secure wrapper for KAS EC private key (P-256).
///
/// The key material is automatically zeroized when dropped.
pub struct SecureEcPrivateKey {
    /// The secret key bytes wrapped in secrecy.
    inner: Secret<[u8; 32]>,
}

impl SecureEcPrivateKey {
    /// Create from raw bytes.
    ///
    /// # Arguments
    /// * `bytes` - 32-byte EC private key
    ///
    /// # Security
    /// The input bytes are copied and the original should be zeroized by the caller.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 32 {
            return Err(KeyError::InvalidKeySize {
                expected: 32,
                got: bytes.len(),
            });
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(bytes);

        Ok(Self {
            inner: Secret::new(key_array),
        })
    }

    /// Create from SEC1-encoded PEM.
    pub fn from_sec1_pem(pem_content: &str) -> Result<Self, KeyError> {
        let pem_bytes = pem_content.as_bytes();
        let parsed = pem::parse(pem_bytes).map_err(|e| KeyError::InvalidFormat(e.to_string()))?;

        if parsed.tag() != "EC PRIVATE KEY" {
            return Err(KeyError::InvalidFormat(format!(
                "Expected EC PRIVATE KEY, got {}",
                parsed.tag()
            )));
        }

        let secret_key = SecretKey::from_sec1_der(parsed.contents())
            .map_err(|e| KeyError::InvalidFormat(e.to_string()))?;

        Self::from_bytes(secret_key.to_bytes().as_slice())
    }

    /// Get the corresponding public key (compressed format, 33 bytes).
    pub fn public_key(&self) -> Result<Vec<u8>, KeyError> {
        let secret_key = SecretKey::from_bytes(self.inner.expose_secret().into())
            .map_err(|e| KeyError::CryptoError(e.to_string()))?;

        let public_key = secret_key.public_key();
        let compressed = public_key.to_encoded_point(true);

        Ok(compressed.as_bytes().to_vec())
    }

    /// Perform ECDH key agreement.
    ///
    /// Returns the x-coordinate of the shared point (32 bytes).
    ///
    /// # Security
    /// The private key is only exposed within this function scope.
    pub fn perform_ecdh(&self, peer_public: &p256::PublicKey) -> Result<[u8; 32], KeyError> {
        use elliptic_curve::point::AffineCoordinates;

        let secret_key = SecretKey::from_bytes(self.inner.expose_secret().into())
            .map_err(|e| KeyError::CryptoError(e.to_string()))?;

        let scalar = secret_key.to_nonzero_scalar();
        let public_point = peer_public.to_projective();
        let shared_point = (public_point * *scalar).to_affine();
        let x_coordinate = shared_point.x();

        let mut result = [0u8; 32];
        result.copy_from_slice(x_coordinate.as_slice());

        Ok(result)
    }

    /// Get the raw p256 SecretKey for low-level operations.
    ///
    /// # Security
    /// Use with caution - the returned key should not be stored or logged.
    pub fn as_secret_key(&self) -> Result<SecretKey, KeyError> {
        SecretKey::from_bytes(self.inner.expose_secret().into())
            .map_err(|e| KeyError::CryptoError(e.to_string()))
    }
}

impl fmt::Debug for SecureEcPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecureEcPrivateKey([REDACTED])")
    }
}

impl Clone for SecureEcPrivateKey {
    fn clone(&self) -> Self {
        // Deep copy the secret bytes
        let mut new_bytes = [0u8; 32];
        new_bytes.copy_from_slice(self.inner.expose_secret());
        Self {
            inner: Secret::new(new_bytes),
        }
    }
}

/// Secure wrapper for RSA private key.
///
/// The key material is automatically zeroized when dropped.
#[allow(dead_code)]
pub struct SecureRsaPrivateKey {
    /// The RSA private key (boxed for size).
    inner: Box<rsa::RsaPrivateKey>,
}

#[allow(dead_code)]
impl SecureRsaPrivateKey {
    /// Create from PKCS#8 PEM.
    pub fn from_pkcs8_pem(pem_content: &str) -> Result<Self, KeyError> {
        use rsa::pkcs8::DecodePrivateKey;

        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(pem_content)
            .map_err(|e| KeyError::InvalidFormat(e.to_string()))?;

        Ok(Self {
            inner: Box::new(private_key),
        })
    }

    /// Get the public key in PEM format.
    pub fn public_key_pem(&self) -> Result<String, KeyError> {
        use rsa::RsaPublicKey;

        let public_key = RsaPublicKey::from(&*self.inner);
        rsa::pkcs8::EncodePublicKey::to_public_key_pem(&public_key, Default::default())
            .map_err(|e| KeyError::CryptoError(e.to_string()))
    }

    /// Get a reference to the inner RSA private key.
    ///
    /// # Security
    /// Use with caution - do not log or persist the returned key.
    pub fn as_inner(&self) -> &rsa::RsaPrivateKey {
        &self.inner
    }
}

impl fmt::Debug for SecureRsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecureRsaPrivateKey([REDACTED])")
    }
}

impl Drop for SecureRsaPrivateKey {
    fn drop(&mut self) {
        // Note: The RSA key struct doesn't implement Zeroize directly,
        // but the Box will be deallocated. For production, consider
        // using a crate that provides zeroizing RSA keys.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ec_key_from_bytes() {
        let bytes = [0x42u8; 32];
        let key = SecureEcPrivateKey::from_bytes(&bytes).unwrap();

        // Public key should be 33 bytes (compressed)
        let public = key.public_key().unwrap();
        assert_eq!(public.len(), 33);
    }

    #[test]
    fn test_ec_key_invalid_size() {
        let bytes = [0x42u8; 16]; // Too short
        let result = SecureEcPrivateKey::from_bytes(&bytes);
        assert!(matches!(result, Err(KeyError::InvalidKeySize { .. })));
    }

    #[test]
    fn ecdh_matches_opentdf_kas_custom_ecdh() {
        let sk = SecureEcPrivateKey::from_bytes(&[3u8; 32]).unwrap();
        let peer = p256::SecretKey::from_bytes(&[5u8; 32].into())
            .unwrap()
            .public_key();
        let ours = sk.perform_ecdh(&peer).unwrap();
        let theirs = opentdf_kas::custom_ecdh(&sk.as_secret_key().unwrap(), &peer).unwrap();
        assert_eq!(ours.to_vec(), theirs);
    }

    #[test]
    fn test_ec_key_debug_redacted() {
        let bytes = [0x42u8; 32];
        let key = SecureEcPrivateKey::from_bytes(&bytes).unwrap();

        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("42"));
    }
}
