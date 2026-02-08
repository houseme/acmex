/// Account credentials and key pair management.
/// This module provides a wrapper around cryptographic key pairs used for
/// ACME account identification and request signing.
use crate::error::Result;
use rcgen::KeyPair as RcgenKeyPair;
use std::fs;
use std::path::Path;

/// A wrapper for cryptographic key pairs (primarily Ed25519).
/// This structure is used to sign ACME requests and identify the account.
pub struct KeyPair(pub RcgenKeyPair);

impl KeyPair {
    /// Generates a new random Ed25519 key pair.
    pub fn generate() -> Result<Self> {
        tracing::debug!("Generating new Ed25519 key pair");
        let key_pair = RcgenKeyPair::generate().map_err(|e| {
            tracing::error!("Failed to generate key pair: {}", e);
            crate::error::AcmeError::crypto(format!("Failed to generate key pair: {}", e))
        })?;
        Ok(Self(key_pair))
    }

    /// Creates a `KeyPair` from a PEM-encoded string.
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        tracing::debug!("Parsing KeyPair from PEM string");
        let key_pair = RcgenKeyPair::from_pem(pem_str).map_err(|e| {
            tracing::error!("Failed to parse PEM key: {}", e);
            crate::error::AcmeError::pem(format!("Failed to parse PEM: {}", e))
        })?;
        Ok(Self(key_pair))
    }

    /// Saves the key pair to a file in PEM format.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let path_ref = path.as_ref();
        tracing::info!("Saving key pair to file: {:?}", path_ref);
        let pem_str = self.0.serialize_pem();
        fs::write(path_ref, pem_str).map_err(|e| {
            tracing::error!("Failed to write key file {:?}: {}", path_ref, e);
            e.into()
        })?;
        Ok(())
    }

    /// Loads a key pair from a PEM-encoded file.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path_ref = path.as_ref();
        tracing::info!("Loading key pair from file: {:?}", path_ref);
        let content = fs::read_to_string(path_ref).map_err(|e| {
            tracing::error!("Failed to read key file {:?}: {}", path_ref, e);
            e.into()
        })?;
        Self::from_pem(&content)
    }

    /// Serializes the key pair to a PEM-formatted string.
    pub fn serialize_pem(&self) -> String {
        self.0.serialize_pem()
    }

    /// Returns the raw bytes of the public key.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.public_key_raw().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = KeyPair::generate();
        assert!(keypair.is_ok());
    }

    #[test]
    fn test_from_pem() {
        let keypair1 = KeyPair::generate().expect("Failed to generate key pair");
        let pem_content = keypair1.serialize_pem();

        let keypair2 = KeyPair::from_pem(&pem_content).expect("Failed to parse from PEM");
        assert_eq!(
            keypair1.serialize_pem(),
            keypair2.serialize_pem(),
            "PEM should match after round trip"
        );
    }
}
