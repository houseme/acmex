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
pub mod cli;
pub mod client;
pub mod crypto;
pub mod dns;
pub mod error;
pub mod metrics;
pub mod order;
pub mod protocol;
pub mod renewal;
pub mod storage;
pub mod transport;
pub mod types;

// Re-exports for convenience
pub use account::{Account, AccountManager, KeyPair};
pub use challenge::{
    ChallengeSolver, ChallengeSolverRegistry, Dns01Solver, DnsProvider, Http01Solver,
    MockDnsProvider,
};
pub use client::{AcmeClient, AcmeConfig, CertificateBundle};
#[cfg(feature = "dns-cloudflare")]
pub use dns::CloudFlareDnsProvider;
#[cfg(feature = "dns-digitalocean")]
pub use dns::DigitalOceanDnsProvider;
#[cfg(feature = "dns-linode")]
pub use dns::LinodeDnsProvider;
#[cfg(feature = "dns-route53")]
pub use dns::Route53DnsProvider;
pub use error::{AcmeError, Result};
pub use metrics::{HealthStatus, MetricsRegistry};
pub use order::{
    parse_certificate_chain, verify_certificate_domains, Authorization, Challenge, CsrGenerator, FinalizationRequest,
    NewOrderRequest, Order, OrderManager,
};
pub use protocol::{Directory, DirectoryManager, Jwk, JwsSigner, NonceManager};
pub use renewal::{RenewalHook, RenewalScheduler};
#[cfg(feature = "redis")]
pub use storage::RedisStorage;
pub use storage::{EncryptedStorage, FileStorage};
pub use types::{
    AuthorizationStatus, ChallengeType, Contact, Identifier, OrderStatus, RevocationReason,
};

/// Prelude module with commonly used types
pub mod prelude {
    pub use crate::{
        account::{Account, AccountManager, KeyPair}, crypto::{Base64Encoding, Sha256Hash},
        error::{AcmeError, Result},
        order::{Authorization, Challenge, FinalizationRequest, NewOrderRequest, Order},
        protocol::{Directory, DirectoryManager, Jwk, JwsSigner, NonceManager},
        transport::HttpClient,
        types::{
            AuthorizationStatus, ChallengeType, Contact, Identifier, OrderStatus, RevocationReason,
        },
        AcmeClient,
        AcmeConfig,
    };
}
