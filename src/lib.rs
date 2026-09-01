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
pub mod application;
pub mod ca;
pub mod ca_backend;
pub mod certificate;
pub mod challenge;
pub mod cli;
pub mod client;
pub mod config;
pub mod crypto;
pub mod dns;
pub mod domain;
pub mod error;
pub mod metrics;
pub mod notifications;
pub mod orchestrator;
pub mod order;
pub mod protocol;
pub mod renewal;
pub mod repository;
pub mod scheduler;
pub mod server;
pub mod storage;
pub mod transport;
pub mod types;
pub mod workflow;

// Re-exports for convenience
pub use account::{Account, AccountManager, KeyPair, KeyRollover};
pub use application::{
    ActorContext, ApplicationServiceBuilder, CertificateApplication, CertificateQuery,
    CreateCertificateIntent, DeployCertificate, IntentView, IssueCertificate, OperationView,
    RenewCertificate, RepositoryCertificateApplication, RevokeCertificate, VersionView,
};
pub use ca::{CAConfig, CertificateAuthority, Environment};
pub use certificate::{CertificateChain, CertificateSubjectAltNames};
pub use challenge::{
    ACME_TLS_ALPN_PROTOCOL, CachingDnsResolver, ChallengeSolver, ChallengeSolverRegistry,
    Dns01Solver, DnsCache, DnsProvider, FakeHttpEdge, FakeTlsEdge, Http01Presenter, Http01Solver,
    HttpChallengeEdge, HttpChallengeRoute, HttpRouteLease, HttpRouteState, MockDnsProvider,
    TlsAlpn01Presenter, TlsAlpn01Solver, TlsChallengeEdge, TlsChallengeRoute, TlsRouteLease,
    TlsRouteState, TokenRegistry, ValidationCertificate, build_tls_alpn_validation_cert,
    http01_host_header, http01_url, ip_validation_sni, tls_alpn_validation_sni,
};
pub use client::{AcmeClient, AcmeConfig, CertificateBundle};
pub use config::{
    AcmeSettings, ChallengeSettings, Config, FileRepositoryConfig, MigrationSettings,
    RenewalSettings, RepositorySettings, StorageSettings,
};
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
pub use domain::{
    CaPolicy, CertificateIntent, CertificateLineage, CertificateVersion, ChallengeSet,
    DnsIdentifier, IdentifierSet, KeyPolicy, KeyRef, RenewalPolicy, ValidationPolicy,
    compatible_challenges, validate_order_policy,
};
pub use error::{AcmeError, Result};
pub use metrics::{HealthStatus, MetricsRegistry};
pub use notifications::{EventType, WebhookClient, WebhookConfig, WebhookEvent, WebhookManager};
pub use orchestrator::{CertificateProvisioner, DomainValidator, Orchestrator};
pub use order::{
    Authorization, CertificateRevocation, Challenge, CsrGenerator, FinalizationRequest,
    NewOrderRequest, Order, OrderManager, parse_certificate_chain, verify_certificate_domains,
    verify_certificate_identifiers,
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
pub use workflow::{EngineConfig, StepExecutor, StepResult, WorkflowEngine};

/// Prelude module with commonly used types
pub mod prelude {
    pub use crate::{
        AcmeClient, AcmeConfig,
        account::{Account, AccountManager, KeyPair, KeyRollover},
        application::{
            ActorContext, ApplicationServiceBuilder, CertificateApplication,
            CreateCertificateIntent, IssueCertificate, RenewCertificate,
        },
        certificate::{CertificateChain, CertificateSubjectAltNames},
        crypto::{Base64Encoding, Sha256Hash},
        domain::{
            CertificateIntent, CertificateLineage, CertificateVersion, DnsIdentifier, Identifier,
            IdentifierSet, KeyRef, compatible_challenges, validate_order_policy,
        },
        error::{AcmeError, Result},
        orchestrator::{CertificateProvisioner, DomainValidator, Orchestrator},
        order::{
            Authorization, CertificateRevocation, Challenge, FinalizationRequest, NewOrderRequest,
            Order, verify_certificate_identifiers,
        },
        protocol::{Directory, DirectoryManager, Jwk, JwsSigner, NonceManager},
        scheduler::{AdvancedRenewalScheduler, CleanupScheduler},
        transport::HttpClient,
        types::{AuthorizationStatus, ChallengeType, Contact, OrderStatus, RevocationReason},
    };
}
