/// Account credentials and key pair management
use crate::error::Result;
use std::fs;
use std::path::Path;

/// KeyPair wrapper for Ed25519 keys
pub struct KeyPair {
    key_pair: ring::signature::Ed25519KeyPair,
    pkcs8_bytes: Vec<u8>,
}

impl KeyPair {
    /// Generate a new Ed25519 key pair
    pub fn generate() -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| crate::error::AcmeError::crypto("Failed to generate Ed25519 key pair"))?;

        let key_pair =
            ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).map_err(|_| {
                crate::error::AcmeError::crypto("Failed to create Ed25519 key pair from PKCS8")
            })?;

        Ok(Self {
            key_pair,
            pkcs8_bytes: pkcs8_bytes.as_ref().to_vec(),
        })
    }

    /// Create KeyPair from PKCS8 encoded bytes
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self> {
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes)
            .map_err(|_| crate::error::AcmeError::crypto("Invalid PKCS8 bytes for Ed25519 key"))?;

        Ok(Self {
            key_pair,
            pkcs8_bytes: pkcs8_bytes.to_vec(),
        })
    }

    /// Create KeyPair from PEM encoded string
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let pem = pem::parse(pem_str)
            .map_err(|e| crate::error::AcmeError::pem(format!("Failed to parse PEM: {}", e)))?;

        if pem.tag() != "PRIVATE KEY" {
            return Err(crate::error::AcmeError::pem(
                "Expected PRIVATE KEY, got: ".to_string() + pem.tag(),
            ));
        }

        Self::from_pkcs8(&pem.contents())
    }

    /// Get PKCS8 encoded bytes
    pub fn to_pkcs8(&self) -> &[u8] {
        &self.pkcs8_bytes
    }

    /// Save key pair to PEM file
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let pem = pem::encode(&pem::Pem::new(
            String::from("PRIVATE KEY"),
            self.pkcs8_bytes.clone(),
        ));
        fs::write(path, pem)?;
        Ok(())
    }

    /// Load key pair from PEM file
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_pem(&content)
    }

    /// Get reference to inner key pair
    pub fn inner(&self) -> &ring::signature::Ed25519KeyPair {
        &self.key_pair
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        use ring::signature::KeyPair;
        self.key_pair.public_key().as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_keypair() {
        let keypair = KeyPair::generate().expect("Failed to generate key pair");
        let public_key = keypair.public_key_bytes();
        assert_eq!(
            public_key.len(),
            32,
            "Ed25519 public key should be 32 bytes"
        );
    }

    #[test]
    fn test_from_pkcs8() {
        let keypair1 = KeyPair::generate().expect("Failed to generate key pair");
        let pkcs8_bytes = keypair1.to_pkcs8();

        let keypair2 = KeyPair::from_pkcs8(pkcs8_bytes).expect("Failed to create from PKCS8");
        assert_eq!(
            keypair1.public_key_bytes(),
            keypair2.public_key_bytes(),
            "Public keys should match"
        );
    }

    #[test]
    fn test_pem_round_trip() {
        let keypair1 = KeyPair::generate().expect("Failed to generate key pair");
        let public_key1 = keypair1.public_key_bytes().to_vec();

        let dir = TempDir::new().expect("Failed to create temp dir");
        let file_path = dir.path().join("test_key.pem");

        keypair1
            .save_to_file(&file_path)
            .expect("Failed to save key pair");

        let keypair2 = KeyPair::load_from_file(&file_path).expect("Failed to load key pair");
        let public_key2 = keypair2.public_key_bytes().to_vec();

        assert_eq!(
            public_key1, public_key2,
            "Public keys should match after round trip"
        );
    }

    #[test]
    fn test_from_pem() {
        let keypair1 = KeyPair::generate().expect("Failed to generate key pair");
        let pem_content = pem::encode(&pem::Pem::new(
            String::from("PRIVATE KEY"),
            keypair1.to_pkcs8().to_vec(),
        ));

        let keypair2 = KeyPair::from_pem(&pem_content).expect("Failed to parse from PEM");
        assert_eq!(
            keypair1.public_key_bytes(),
            keypair2.public_key_bytes(),
            "Public keys should match"
        );
    }
}
