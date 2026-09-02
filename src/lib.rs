//! # AcmeX — ACME v2 certificate lifecycle control plane (library + CLI)
//!
//! AcmeX is a Rust implementation of ACME v2 (RFC 8555) with the surrounding
//! lifecycle machinery a production deployment actually needs: durable,
//! restart-safe operations; typed identifiers (DNS names, wildcards, IPv4,
//! IPv6 per RFC 8738); RFC 9773 (ARI) renewal windows; managed or external
//! keys; and atomic delivery to downstream sinks with health-gated
//! activation and rollback.
//!
//! The crate is dual-use:
//!
//! * **as a library** — pull `acmex` into your own service and drive the
//!   same pipeline through [`application::ApplicationServiceBuilder`] and
//!   [`server::worker`];
//! * **as a CLI** — the `acmex` binary wraps the same engine:
//!   `acmex init` scaffolds a project, `acmex obtain --wait` requests a
//!   certificate end to end, `acmex serve` runs the API + worker, and
//!   `acmex daemon` runs renewal scanning + execution without the API.
//!
//! ## Architecture in one screen
//!
//! ```text
//! Intent (desired state)
//!   └─ ApplicationService  ── submit ──▶  Operation (durable, 17-step spine)
//!        │                                      │
//!        │                               WorkflowEngine (one step at a
//!        │                               time, every step persisted,
//!        │                               crash-resumable, lease-fenced)
//!        │                                      │
//!   CertificateQuery ◀── views ──    CaBackend (JWS, badNonce, Retry-After,
//!        │                            ARI) · Presenters (DNS-01/HTTP-01/
//!        │                            TLS-ALPN-01) · KeyProvider · Sinks
//!        ▼
//!   CertificateVersion (immutable) ──▶ Deployment (stage → activate →
//!                                       health check → rollback) ──▶ active
//! ```
//!
//! ## Library quick start
//!
//! Submit an issuance request and drive it with the embedded engine:
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! use acmex::application::{
//!     ActorContext, ApplicationServiceBuilder, CertificateApplication,
//!     CertificateQuery, CreateCertificateIntent, IssueCertificate,
//! };
//! use acmex::config::Config;
//! use acmex::metrics::MetricsRegistry;
//! use acmex::server::worker::{self, WorkflowWorkerSettings};
//!
//! #[tokio::main]
//! async fn main() -> acmex::Result<()> {
//!     // Any `Config` works; `Config::default()` targets Let's Encrypt staging.
//!     let config = Config::default();
//!
//!     // 1. Application service over the durable repository (file or memory).
//!     let (service, repositories) =
//!         ApplicationServiceBuilder::from_config(&config).await?.build()?;
//!
//!     // 2. Declare the desired certificate (idempotent per key).
//!     let intent = service
//!         .create_intent(CreateCertificateIntent {
//!             context: ActorContext::default(),
//!             identifiers: vec!["example.com".to_string()],
//!             ca_policy: Default::default(),
//!             validation_policy: Default::default(),
//!             key_policy: Default::default(),
//!             renewal_policy: Default::default(),
//!             delivery_targets: Vec::new(),
//!             idempotency_key: "my-intent-1".to_string(),
//!         })
//!         .await?;
//!
//!     // 3. Submit the issue operation (returns immediately; durable).
//!     let operation = service
//!         .issue(IssueCertificate {
//!             context: ActorContext::default(),
//!             intent_id: intent.id.clone(),
//!             idempotency_key: format!("issue-{}", intent.id),
//!         })
//!         .await?;
//!
//!     // 4. Build the production engine (CA backend, presenters, keys,
//!     //    sinks) and drive the operation to a terminal state.
//!     let engine = worker::build_engine_from_config(
//!         &config,
//!         repositories,
//!         Arc::new(MetricsRegistry::new()),
//!         WorkflowWorkerSettings::default(),
//!     )
//!     .await?;
//!     let record = engine
//!         .run_until_terminal(&operation.id, Duration::from_secs(900))
//!         .await?;
//!     println!("operation finished: {:?}", record.status);
//!     Ok(())
//! }
//! ```
//!
//! ## Feature flags
//!
//! Crypto defaults to `aws-lc-rs` (`ring` selectable); each DNS provider is
//! behind its own feature (`dns-cloudflare`, `dns-route53`, ...); `redis`
//! enables Redis storage. See `Cargo.toml` for the full list and
//! `docs/roadmap/v0.9.0/FEATURE_MATRIX.md` for validation status.
//!
//! ## Module map
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`domain`] | Typed identifiers, intents, lineages, versions, operations |
//! | [`repository`] | Pluggable durable state (memory/file), CAS, leases, outbox |
//! | [`workflow`] | The step-wise durable engine and the real step executors |
//! | [`application`] | The unified use-case API (create/issue/renew/revoke/deploy) |
//! | [`ca_backend`] | RFC 8555 session, badNonce/Retry-After, ARI, capabilities |
//! | [`challenge`] | Challenge sessions, leases, presenters, cleanup |
//! | [`dns`] | Provider factory, zone discovery, propagation quorum |
//! | [`key`] | Managed/external keys and CSRs |
//! | [`delivery`] | Sinks, deployment orchestration, activation gating |
//! | [`renewal`] | ARI-first renewal controller |
//! | [`server`] | Axum API v1, auth, health, metrics endpoint, worker wiring |
//! | [`cli`] | The `acmex` binary commands |
//!

// Module declarations
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
pub mod delivery;
pub mod dns;
pub mod domain;
pub mod error;
pub mod key;
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
    ChallengeLeaseView, ChallengeSessionView, CreateCertificateIntent, DeployCertificate,
    IntentView, IssueCertificate, OperationView, Permission, RenewCertificate,
    RepositoryCertificateApplication, RevokeCertificate, UpdateCertificateIntent, VersionView,
};
pub use ca::{CAConfig, CertificateAuthority, Environment};
pub use ca_backend::{DirectoryAriProvider, InstrumentedAcmeTransport};
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
pub use delivery::{
    CertificateMaterial, CertificateMaterialBuilder, CertificateMaterialRef, CertificateSink,
    CleanupOutcome, DeploymentActivationOutcome, DeploymentGate, DeploymentHealth,
    DeploymentOrchestrator, DeploymentSpec, FakeAgentCertificateSink, FileCertificateSink,
    HttpAgentSink, StagedDeployment,
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
    DeliveryRequirement, DeliveryTargetKind, DeploymentId, DnsIdentifier, IdentifierSet,
    KeyAlgorithm, KeyId, KeyManagementMode, KeyPolicy, KeyRef, LineageId, RenewalPolicy, TargetId,
    ValidationPolicy, VersionId, VersionState, compatible_challenges, validate_order_policy,
};
pub use error::{AcmeError, Result};
pub use key::{
    CreateCsr, CreateKey, CsrArtifact, DestroyOutcome, ExportAuthorization, ExternalCsr,
    KeyProvider, PublicKeyInfo, SecretBytes, SoftwareKeyProvider,
};
pub use metrics::{HealthStatus, MetricsRegistry};
pub use notifications::{
    EventType, OutboxConsumer, OutboxConsumerConfig, OutboxConsumerReport, OutboxDelivery,
    WebhookClient, WebhookConfig, WebhookEvent, WebhookManager, WebhookVerificationError,
    verify_webhook_signature,
};
pub use orchestrator::{CertificateProvisioner, DomainValidator, Orchestrator};
pub use order::{
    Authorization, CertificateRevocation, Challenge, CsrGenerator, FinalizationRequest,
    NewOrderRequest, Order, OrderManager, parse_certificate_chain, verify_certificate_domains,
    verify_certificate_identifiers,
};
pub use protocol::{Directory, DirectoryManager, Jwk, JwsSigner, NonceManager};
pub use renewal::{
    ControllerRenewalScheduler, RenewalActivationOutcome, RenewalController,
    RenewalControllerConfig, RenewalDecision, RenewalInfoProvider, RenewalPriority, RenewalReason,
    RenewalScanReport, RenewalWindowSource, calculate_decision,
};
#[allow(deprecated)]
pub use renewal::{RenewalHook, SimpleRenewalScheduler};
#[allow(deprecated)]
pub use scheduler::{AdvancedRenewalScheduler, CleanupScheduler, RenewalScheduler};
pub use server::{
    HealthCheck, WebhookHandler, start_server,
    worker::{
        WorkflowWorkerComponents, WorkflowWorkerSettings, build_engine_from_config,
        register_executors, spawn_from_config,
    },
};
#[cfg(feature = "redis")]
pub use storage::RedisStorage;
pub use storage::{EncryptedStorage, FileStorage};
pub use types::{
    AuthorizationStatus, ChallengeType, Contact, Identifier, OrderStatus, RevocationReason,
};
pub use workflow::{
    ActivateDeploymentStep, CompleteStep, CreateCsrStep, DownloadCertificateStep, EngineConfig,
    FinalizeOrderStep, IssuanceStepDeps, PersistVersionStep, PlanStep, ScheduleDeploymentsStep,
    StageDeploymentStep, StepExecutor, StepResult, SubmitRevocationStep, VerifyCertificateStep,
    VerifyDeploymentStep, WaitOrderStep, WorkflowEngine,
};

/// Prelude module with commonly used types
pub mod prelude {
    #[allow(deprecated)]
    pub use crate::scheduler::AdvancedRenewalScheduler;
    pub use crate::{
        AcmeClient, AcmeConfig,
        account::{Account, AccountManager, KeyPair, KeyRollover},
        application::{
            ActorContext, ApplicationServiceBuilder, CertificateApplication,
            CreateCertificateIntent, IssueCertificate, Permission, RenewCertificate,
        },
        certificate::{CertificateChain, CertificateSubjectAltNames},
        crypto::{Base64Encoding, Sha256Hash},
        delivery::{
            CertificateMaterialBuilder, CertificateSink, DeploymentOrchestrator, DeploymentSpec,
            FakeAgentCertificateSink, FileCertificateSink, HttpAgentSink,
        },
        domain::{
            CertificateIntent, CertificateLineage, CertificateVersion, DnsIdentifier, Identifier,
            IdentifierSet, KeyAlgorithm, KeyId, KeyManagementMode, KeyRef, LineageId, TargetId,
            VersionId, VersionState, compatible_challenges, validate_order_policy,
        },
        error::{AcmeError, Result},
        key::{KeyProvider, SecretBytes, SoftwareKeyProvider},
        orchestrator::{CertificateProvisioner, DomainValidator, Orchestrator},
        order::{
            Authorization, CertificateRevocation, Challenge, FinalizationRequest, NewOrderRequest,
            Order, verify_certificate_identifiers,
        },
        protocol::{Directory, DirectoryManager, Jwk, JwsSigner, NonceManager},
        renewal::{
            ControllerRenewalScheduler, RenewalActivationOutcome, RenewalController,
            RenewalControllerConfig, RenewalDecision, RenewalPriority, RenewalWindowSource,
        },
        scheduler::CleanupScheduler,
        server::worker::{WorkflowWorkerSettings, build_engine_from_config},
        transport::HttpClient,
        types::{AuthorizationStatus, ChallengeType, Contact, OrderStatus, RevocationReason},
        workflow::{EngineConfig, StepExecutor, StepResult, WorkflowEngine},
    };
}
