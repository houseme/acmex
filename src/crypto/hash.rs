/// Hashing utilities supporting multiple algorithms.
/// This module provides a unified interface for common cryptographic hash functions
/// used in ACME operations, such as challenge validation and thumbprint calculation.
use crate::error::Result;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Supported hashing algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (Recommended for DNS-01 and general ACME use).
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Computes the hash of the provided data using the selected algorithm.
    pub fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        tracing::debug!("Computing {} hash for {} bytes of data", self, data.len());
        match self {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
        }
    }

    /// Computes the hash and returns it as a hex-encoded string.
    pub fn hash_hex(&self, data: &[u8]) -> Result<String> {
        let hash = self.hash(data)?;
        Ok(crate::crypto::encoding::HexEncoding::encode(&hash))
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "SHA256"),
            HashAlgorithm::Sha384 => write!(f, "SHA384"),
            HashAlgorithm::Sha512 => write!(f, "SHA512"),
        }
    }
}

/// A specialized utility for SHA-256 hashing.
pub struct Sha256Hash;

impl Sha256Hash {
    /// Computes the SHA-256 hash of the provided data.
    pub fn hash(data: &[u8]) -> Result<Vec<u8>> {
        HashAlgorithm::Sha256.hash(data)
    }

    /// Computes the SHA-256 hash and returns it as a hex-encoded string.
    pub fn hash_hex(data: &[u8]) -> Result<String> {
        let hash = Self::hash(data)?;
        Ok(crate::crypto::encoding::HexEncoding::encode(&hash))
    }

    /// Computes the SHA-256 hash and returns it as a URL-safe Base64-encoded string (no padding).
    pub fn hash_base64(data: &[u8]) -> Result<String> {
        use base64::Engine;
        let hash = Self::hash(data)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash = Sha256Hash::hash(data).unwrap();

        // Known SHA256("test data") value
        assert_eq!(
            hex::encode(&hash),
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_sha256_hash_hex() {
        let data = b"hello";
        let hex = Sha256Hash::hash_hex(data).unwrap();
        assert!(!hex.is_empty());
        assert_eq!(hex.len(), 64); // SHA256 produces 64 hex characters
    }

    #[test]
    fn test_sha256_hash_base64() {
        let data = b"test";
        let base64 = Sha256Hash::hash_base64(data).unwrap();
        assert!(!base64.is_empty());
    }
}
