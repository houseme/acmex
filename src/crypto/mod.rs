/// Cryptographic primitives layer.
/// This module provides foundational cryptographic functionality including
/// key generation, digital signatures, hashing, and various encoding schemes
/// required for the ACME protocol and certificate management.
///
/// The architecture is designed to be modular, allowing for easy extension
/// of supported algorithms and encoding formats.

pub mod encoding;
pub mod hash;
pub mod keypair;
pub mod signer;

// Re-exports for convenient access to core cryptographic utilities
pub use encoding::{Base64Encoding, PemEncoding};
pub use hash::{HashAlgorithm, Sha256Hash};
pub use keypair::{KeyPairGenerator, KeyType};
pub use signer::{Signature, Signer};

/// Initializes the cryptographic subsystem.
/// Currently a placeholder for any global crypto initialization (e.g., OpenSSL or ring).
pub fn init() {
    tracing::info!("Initializing cryptographic subsystem");
}
