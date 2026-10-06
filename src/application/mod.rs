//! Application service boundary for certificate lifecycle use cases.
//!
//! API handlers, CLI commands and schedulers should convert their transport
//! inputs into these commands and then call this module. The service persists
//! durable operations and returns immediately; workers advance those operations
//! through the workflow engine.

mod account;
mod service;
mod types;

pub use account::{
    AccountApplication, AccountKeyRolloverView, RepositoryAccountApplication, RolloverAccountKey,
    default_account_id,
};
pub use service::{ApplicationServiceBuilder, RepositoryCertificateApplication};
pub use types::{
    ActorContext, CancelOperation, CertificateApplication, CertificateQuery, ChallengeLeaseView,
    ChallengeSessionView, CreateCertificateIntent, DeployCertificate, IntentView, IssueCertificate,
    OperationView, Permission, RenewCertificate, RevokeCertificate, UpdateCertificateIntent,
    VersionView,
};
