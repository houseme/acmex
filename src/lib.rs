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
pub mod ca;
pub mod certificate;
pub mod challenge;
pub mod cli;
pub mod client;
pub mod config;
pub mod crypto;
pub mod dns;
pub mod error;
pub mod metrics;
pub mod notifications;
pub mod orchestrator;
pub mod order;
pub mod protocol;
pub mod renewal;
pub mod scheduler;
pub mod server;
pub mod storage;
pub mod transport;
pub mod types;

// Re-exports for convenience
pub use account::{Account, AccountManager, KeyPair, KeyRollover};
pub use ca::{CAConfig, CertificateAuthority, Environment};
pub use certificate::CertificateChain;
pub use challenge::{
    CachingDnsResolver, ChallengeSolver, ChallengeSolverRegistry, Dns01Solver, DnsCache,
    DnsProvider, Http01Solver, MockDnsProvider, TlsAlpn01Solver,
};
pub use client::{AcmeClient, AcmeConfig, CertificateBundle};
pub use config::{AcmeSettings, ChallengeSettings, Config, RenewalSettings, StorageSettings};
#[cfg(feature = "dns-alibaba")]
pub use dns::AlibabaCloudDnsProvider;
#[cfg(feature = "dns-azure")]
pub use dns::AzureDnsProvider;
#[cfg(feature = "dns-cloudns")]
pub use dns::ClouDnsProvider;
#[cfg(feature = "dns-cloudflare")]
pub use dns::CloudFlareDnsProvider;
#[cfg(feature = "dns-digitalocean")]
pub use dns::DigitalOceanDnsProvider;
#[cfg(feature = "dns-godaddy")]
pub use dns::GodaddyDnsProvider;
#[cfg(feature = "dns-google")]
pub use dns::GoogleCloudDnsProvider;
#[cfg(feature = "dns-huawei")]
pub use dns::HuaweiCloudDnsProvider;
#[cfg(feature = "dns-linode")]
pub use dns::LinodeDnsProvider;
#[cfg(feature = "dns-route53")]
pub use dns::Route53DnsProvider;
#[cfg(feature = "dns-tencent")]
pub use dns::TencentCloudDnsProvider;
pub use error::{AcmeError, Result};
pub use metrics::{HealthStatus, MetricsRegistry};
pub use notifications::{EventType, WebhookClient, WebhookConfig, WebhookEvent, WebhookManager};
pub use orchestrator::{CertificateProvisioner, DomainValidator, Orchestrator};
pub use order::{
    Authorization, CertificateRevocation, Challenge, CsrGenerator, FinalizationRequest,
    NewOrderRequest, Order, OrderManager, parse_certificate_chain, verify_certificate_domains,
};
pub use protocol::{Directory, DirectoryManager, Jwk, JwsSigner, NonceManager};
pub use renewal::{RenewalHook, SimpleRenewalScheduler};
pub use scheduler::{AdvancedRenewalScheduler, CleanupScheduler, RenewalScheduler};
pub use server::{HealthCheck, WebhookHandler, start_server};
#[cfg(feature = "redis")]
pub use storage::RedisStorage;
pub use storage::{EncryptedStorage, FileStorage};
pub use types::{
    AuthorizationStatus, ChallengeType, Contact, Identifier, OrderStatus, RevocationReason,
};

/// Prelude module with commonly used types
pub mod prelude {
    pub use crate::{
        AcmeClient, AcmeConfig,
        account::{Account, AccountManager, KeyPair, KeyRollover},
        certificate::CertificateChain,
        crypto::{Base64Encoding, Sha256Hash},
        error::{AcmeError, Result},
        orchestrator::{CertificateProvisioner, DomainValidator, Orchestrator},
        order::{
            Authorization, CertificateRevocation, Challenge, FinalizationRequest, NewOrderRequest,
            Order,
        },
        protocol::{Directory, DirectoryManager, Jwk, JwsSigner, NonceManager},
        scheduler::{AdvancedRenewalScheduler, CleanupScheduler},
        transport::HttpClient,
        types::{
            AuthorizationStatus, ChallengeType, Contact, Identifier, OrderStatus, RevocationReason,
        },
    };
}
