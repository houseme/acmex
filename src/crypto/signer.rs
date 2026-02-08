/// Signer utilities providing a unified interface for digital signatures.
/// This module defines the `Signer` trait and implementations for various
/// algorithms used in the ACME protocol, such as HMAC and EdDSA.
use crate::error::{AcmeError, Result};
use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;

/// Represents a digital signature and its associated algorithm.
#[derive(Debug, Clone)]
pub struct Signature {
    /// The raw signature data.
    pub data: Vec<u8>,
    /// The name of the algorithm used to create the signature (e.g., "HS256", "EdDSA").
    pub algorithm: String,
}

impl Signature {
    /// Creates a new `Signature` instance.
    pub fn new(data: Vec<u8>, algorithm: String) -> Self {
        Self { data, algorithm }
    }

    /// Returns the signature data as a URL-safe Base64-encoded string (no padding).
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.data)
    }
}

/// A trait for objects that can sign data.
/// This provides a unified interface for both symmetric (HMAC) and asymmetric (EdDSA, RSA) signing.
pub trait Signer: Send + Sync {
    /// Signs the provided data and returns a `Signature`.
    fn sign(&self, data: &[u8]) -> Result<Signature>;

    /// Returns the name of the signing algorithm.
    fn algorithm(&self) -> &str;

    /// Verifies a signature against the provided data.
    /// Default implementation returns `false` if not overridden.
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool> {
        Ok(false)
    }
}

/// An HMAC-based signer implementation.
pub struct HmacSigner {
    /// The secret key used for signing.
    key: Vec<u8>,
    /// The HMAC algorithm name.
    algorithm: String,
}

impl HmacSigner {
    /// Creates a new `HmacSigner` with the specified key and algorithm.
    pub fn new(key: Vec<u8>, algorithm: String) -> Self {
        Self { key, algorithm }
    }

    /// Creates a new `HmacSigner` using the HS256 (HMAC-SHA256) algorithm.
    pub fn hs256(key: Vec<u8>) -> Self {
        Self::new(key, "HS256".to_string())
    }
}

impl Signer for HmacSigner {
    /// Signs data using the configured HMAC algorithm.
    fn sign(&self, data: &[u8]) -> Result<Signature> {
        tracing::debug!("Signing data with HMAC algorithm: {}", self.algorithm);
        match self.algorithm.as_str() {
            "HS256" | "HMAC-SHA256" => {
                let mac = Hmac::<Sha256>::new_from_slice(&self.key)
                    .map_err(|e| {
                        tracing::error!("Invalid HMAC key: {}", e);
                        AcmeError::crypto(format!("HMAC key error: {}", e))
                    })?;
                let mut mac = mac;
                mac.update(data);
                let result = mac.finalize().into_bytes().to_vec();
                Ok(Signature::new(result, self.algorithm.clone()))
            }
            _ => {
                tracing::error!("Unsupported HMAC algorithm requested: {}", self.algorithm);
                Err(AcmeError::crypto(format!(
                    "Unsupported HMAC algorithm: {}",
                    self.algorithm
                )))
            }
        }
    }

    /// Returns the HMAC algorithm name.
    fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Verifies an HMAC signature.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        tracing::debug!("Verifying HMAC signature with algorithm: {}", self.algorithm);
        match self.algorithm.as_str() {
            "HS256" | "HMAC-SHA256" => {
                let mac = Hmac::<Sha256>::new_from_slice(&self.key)
                    .map_err(|e| {
                        tracing::error!("Invalid HMAC key during verification: {}", e);
                        AcmeError::crypto(format!("HMAC key error: {}", e))
                    })?;
                let mut mac = mac;
                mac.update(data);
                Ok(mac.verify_slice(signature).is_ok())
            }
            _ => {
                tracing::warn!("Verification not supported for algorithm: {}", self.algorithm);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_base64() {
        let sig = Signature::new(vec![1, 2, 3, 4], "test".to_string());
        let base64 = sig.to_base64();
        assert!(!base64.is_empty());
    }

    #[test]
    fn test_hmac_signer() {
        let key = b"secret-key".to_vec();
        let signer = HmacSigner::hs256(key);
        let data = b"hello world";

        let sig = signer.sign(data).unwrap();
        assert_eq!(sig.algorithm, "HS256");
        assert_eq!(sig.data.len(), 32);

        let verified = signer.verify(data, &sig.data).unwrap();
        assert!(verified);

        let wrong_data = b"wrong data";
        let verified_wrong = signer.verify(wrong_data, &sig.data).unwrap();
        assert!(!verified_wrong);
    }
}
