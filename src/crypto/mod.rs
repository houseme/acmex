//! Cryptographic primitives layer.
//! This module provides foundational cryptographic functionality including
//! key generation, digital signatures, hashing, and various encoding schemes
//! required for the ACME protocol and certificate management.
//!
//! The architecture is designed to be modular, allowing for easy extension
//! of supported algorithms and encoding formats.

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
/// Records crypto subsystem startup; the selected backend is initialized lazily by its key and
/// signing primitives.
pub fn init() {
    tracing::info!("Initializing cryptographic subsystem");
}
