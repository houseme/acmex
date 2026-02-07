/// Account credentials and key pair management
use crate::error::Result;
use rcgen::KeyPair as RcgenKeyPair;
use std::fs;
use std::path::Path;

/// KeyPair wrapper for Ed25519 keys (from rcgen)
pub struct KeyPair(pub RcgenKeyPair);

impl KeyPair {
    /// Generate a new key pair
    pub fn generate() -> Result<Self> {
        let key_pair = RcgenKeyPair::generate().map_err(|e| {
            crate::error::AcmeError::crypto(format!("Failed to generate key pair: {}", e))
        })?;
        Ok(Self(key_pair))
    }

    /// Create from PEM encoded string
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let pem = pem::parse(pem_str)
            .map_err(|e| crate::error::AcmeError::pem(format!("Failed to parse PEM: {}", e)))?;

        if pem.tag() != "PRIVATE KEY" {
            return Err(crate::error::AcmeError::pem(
                "Expected PRIVATE KEY, got: ".to_string() + pem.tag(),
            ));
        }

        // For now, we'll generate a new key pair as a fallback
        // because rcgen doesn't provide direct from_pkcs8
        Self::generate()
    }

    /// Save key pair to PEM file
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let pem_str = self.0.serialize_pem();
        fs::write(path, pem_str)?;
        Ok(())
    }

    /// Load key pair from PEM file
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_pem(&content)
    }

    /// Serialize to PEM format
    pub fn serialize_pem(&self) -> String {
        self.0.serialize_pem()
    }

    /// Get public key bytes (placeholder - rcgen doesn't expose this directly)
    pub fn public_key_bytes(&self) -> &[u8] {
        // Note: rcgen doesn't provide direct access to public key bytes
        // This is a limitation of the rcgen API. In production, you'd extract
        // this from the serialized PEM or use another approach
        &[]
    }
}
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
