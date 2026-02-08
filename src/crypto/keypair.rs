/// Key pair management supporting EdDSA (Ed25519) and ECDSA (P-256) keys.
/// This module provides utilities for generating and managing cryptographic keys
/// used for ACME account identification and certificate signing requests.
use crate::error::AcmeError;
use crate::error::Result;

/// Enumeration of supported key types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// EdDSA Ed25519 (Recommended for performance and security).
    Ed25519,
    /// ECDSA P-256.
    EcdsaP256,
    /// ECDSA P-384.
    EcdsaP384,
    /// ECDSA P-521.
    EcdsaP521,
    /// RSA 2048-bit.
    Rsa2048,
    /// RSA 4096-bit.
    Rsa4096,
}

impl KeyType {
    /// Returns the JSON Web Algorithm (JWA) identifier for the key type.
    pub fn jwa_algorithm(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "EdDSA",
            KeyType::EcdsaP256 => "ES256",
            KeyType::EcdsaP384 => "ES384",
            KeyType::EcdsaP521 => "ES512",
            KeyType::Rsa2048 | KeyType::Rsa4096 => "RS256",
        }
    }

    /// Returns the OpenSSL curve name for EC keys, if applicable.
    pub fn openssl_curve(&self) -> Option<&'static str> {
        match self {
            KeyType::EcdsaP256 => Some("prime256v1"),
            KeyType::EcdsaP384 => Some("secp384r1"),
            KeyType::EcdsaP521 => Some("secp521r1"),
            _ => None,
        }
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Ed25519 => write!(f, "Ed25519"),
            KeyType::EcdsaP256 => write!(f, "ECDSA-P256"),
            KeyType::EcdsaP384 => write!(f, "ECDSA-P384"),
            KeyType::EcdsaP521 => write!(f, "ECDSA-P521"),
            KeyType::Rsa2048 => write!(f, "RSA-2048"),
            KeyType::Rsa4096 => write!(f, "RSA-4096"),
        }
    }
}

/// A representation of a public key in JSON Web Key (JWK) format.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JwkPublicKey {
    /// Key type (e.g., "RSA", "EC", "OKP").
    pub kty: String,
    /// Algorithm identifier (e.g., "RS256", "ES256", "EdDSA").
    pub alg: String,
    /// Intended use of the key (typically "sig" for signing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    /// RSA modulus (n).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA public exponent (e).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// Curve name for EC/OKP keys (e.g., "P-256", "Ed25519").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// X coordinate for EC/OKP keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Y coordinate for EC keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// A generator for creating new cryptographic key pairs.
pub struct KeyPairGenerator {
    /// The type of key to generate.
    key_type: KeyType,
}

impl KeyPairGenerator {
    /// Creates a new `KeyPairGenerator` for the specified key type.
    pub fn new(key_type: KeyType) -> Self {
        Self { key_type }
    }

    /// Creates a generator for Ed25519 keys (Recommended).
    pub fn ed25519() -> Self {
        Self::new(KeyType::Ed25519)
    }

    /// Creates a generator for ECDSA P-256 keys.
    pub fn ecdsa_p256() -> Self {
        Self::new(KeyType::EcdsaP256)
    }

    /// Creates a generator for ECDSA P-384 keys.
    pub fn ecdsa_p384() -> Self {
        Self::new(KeyType::EcdsaP384)
    }

    /// Generates a new key pair based on the configured key type.
    pub fn generate(&self) -> Result<rcgen::KeyPair> {
        tracing::info!("Generating new {} key pair", self.key_type);
        match self.key_type {
            KeyType::Ed25519 => rcgen::KeyPair::generate().map_err(|e| {
                tracing::error!("Failed to generate Ed25519 key: {}", e);
                AcmeError::crypto(format!("Failed to generate Ed25519 key: {}", e))
            }),
            _ => {
                tracing::error!(
                    "Key generation for {} is not yet implemented",
                    self.key_type
                );
                Err(AcmeError::crypto(format!(
                    "Key type {} generation not yet implemented",
                    self.key_type
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_type_jwa() {
        assert_eq!(KeyType::Ed25519.jwa_algorithm(), "EdDSA");
        assert_eq!(KeyType::EcdsaP256.jwa_algorithm(), "ES256");
        assert_eq!(KeyType::Rsa2048.jwa_algorithm(), "RS256");
    }

    #[test]
    fn test_generate_ed25519() {
        let generator = KeyPairGenerator::ed25519();
        let result = generator.generate();
        assert!(result.is_ok(), "Ed25519 generation should work");
    }
}
