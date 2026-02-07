//! # AcmeX - ACME v2 Client Library
//!
//! A comprehensive Rust library for interacting with ACME v2 servers (RFC 8555).
//! Supports Let's Encrypt, Google Trust Services, ZeroSSL, and custom ACME implementations.
//!
//! ## Features
//!
//! - **Complete ACME v2 Protocol Support**: Full RFC 8555 implementation
//! - **Multiple Challenge Types**: HTTP-01, DNS-01, TLS-ALPN-01
//! - **Account Management**: Registration, key rollover, deactivation
//! - **Order Management**: Certificate ordering and finalization
//! - **Storage Flexibility**: File-based (default) or Redis-backed storage
//! - **Async/Await**: Built on Tokio for high performance
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use acmex::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> acmex::Result<()> {
//!     // Create a client for Let's Encrypt staging
//!     let config = AcmeConfig::new("https://acme-staging-v02.api.letsencrypt.org/directory");
//!
//!     // ... use the client
//!     Ok(())
//! }
//! ```

// Module declarations
pub mod account;
pub mod challenge;
pub mod error;
pub mod order;
pub mod protocol;
pub mod types;

// Re-exports for convenience
pub use account::{Account, AccountManager, KeyPair};
pub use challenge::{
    ChallengeSolver, ChallengeSolverRegistry, Dns01Solver, DnsProvider, Http01Solver,
    MockDnsProvider,
};
pub use error::{AcmeError, Result};
pub use order::{Authorization, Challenge, FinalizationRequest, NewOrderRequest, Order};
pub use protocol::{Directory, DirectoryManager, Jwk, JwsSigner, NonceManager};
pub use types::{
    AuthorizationStatus, ChallengeType, Contact, Identifier, OrderStatus, RevocationReason,
};

/// Prelude module with commonly used types
pub mod prelude {
    pub use crate::{
        account::{Account, AccountManager, KeyPair},
        error::{AcmeError, Result},
        order::{Authorization, Challenge, FinalizationRequest, NewOrderRequest, Order},
        protocol::{Directory, DirectoryManager, Jwk, JwsSigner, NonceManager},
        types::{
            AuthorizationStatus, ChallengeType, Contact, Identifier, OrderStatus, RevocationReason,
        },
        AcmeConfig,
    };
}

/// ACME client configuration builder
pub struct AcmeConfig {
    /// Directory URL for the ACME server
    pub directory_url: String,

    /// Contacts for account registration
    pub contacts: Vec<Contact>,

    /// Terms of service agreed flag
    pub terms_of_service_agreed: bool,
}

impl AcmeConfig {
    /// Create a new configuration with the given directory URL
    pub fn new(directory_url: impl Into<String>) -> Self {
        Self {
            directory_url: directory_url.into(),
            contacts: Vec::new(),
            terms_of_service_agreed: false,
        }
    }

    /// Add a contact to the configuration
    pub fn with_contact(mut self, contact: Contact) -> Self {
        self.contacts.push(contact);
        self
    }

    /// Set terms of service agreed flag
    pub fn with_tos_agreed(mut self, agreed: bool) -> Self {
        self.terms_of_service_agreed = agreed;
        self
    }

    /// Let's Encrypt staging directory
    pub fn lets_encrypt_staging() -> Self {
        Self::new("https://acme-staging-v02.api.letsencrypt.org/directory")
    }

    /// Let's Encrypt production directory
    pub fn lets_encrypt() -> Self {
        Self::new("https://acme-v02.api.letsencrypt.org/directory")
    }
}
