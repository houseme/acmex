//! Key management: the `KeyProvider` port and its implementations.
//!
//! Two modes (roadmap T10):
//!
//! * **Managed** — AcmeX generates keys and stores them via a secret store
//!   ([`SoftwareKeyProvider`]); `CertificateVersion` only ever references
//!   the key through a [`KeyRef`].
//! * **External CSR** — the caller keeps the private key and submits a CSR;
//!   AcmeX verifies the CSR's self-signature and exact identifier match
//!   ([`validate_external_csr`]) and never sees key material.
//!
//! Account keys and certificate keys are distinct references with distinct
//! policies; export requires explicit authorization.

pub mod external;
pub mod software;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::dns::spec::SecretBytes;
use crate::domain::{Identifier, KeyAlgorithm, KeyId, KeyManagementMode, KeyPolicy, KeyRef};
use crate::error::Result;

pub use external::validate_external_csr;
pub use software::SoftwareKeyProvider;

/// A key creation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateKey {
    /// Key policy (algorithm, exportability).
    pub policy: KeyPolicy,
    /// Idempotency key; the same key yields the same `KeyRef`.
    pub idempotency_key: Option<String>,
}

impl CreateKey {
    /// A request for the given policy.
    pub fn new(policy: KeyPolicy) -> Self {
        Self {
            policy,
            idempotency_key: None,
        }
    }
}

/// A CSR creation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCsr {
    /// The key to sign with.
    pub key: KeyRef,
    /// The exact identifier set the CSR must carry (DNS → dNSName,
    /// IP → iPAddress; never an IP spelled as a dNSName).
    pub identifiers: Vec<Identifier>,
}

/// A produced CSR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrArtifact {
    /// DER encoding.
    pub der: Vec<u8>,
    /// PEM encoding.
    pub pem: String,
}

/// Public key material (safe to expose).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// PEM-encoded public key (SPKI).
    pub pem: String,
    /// The key algorithm.
    pub algorithm: KeyAlgorithm,
}

/// Authorization for exporting a managed private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportAuthorization {
    /// The requesting actor (audited).
    pub actor: String,
    /// Why the export happens (audited).
    pub purpose: String,
    /// The granted permission (validated by the caller's authorizer).
    pub permission: String,
}

impl ExportAuthorization {
    /// An authorization carrying the required `key.export` permission.
    pub fn key_export(actor: impl Into<String>, purpose: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
            purpose: purpose.into(),
            permission: "key.export".to_string(),
        }
    }
}

/// Key destruction outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestroyOutcome {
    /// The key material was destroyed.
    Destroyed,
    /// The key was not found.
    NotFound,
    /// Destruction refused (e.g. referenced by an active version).
    Refused(String),
}

/// The key management port.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Provider name (`software`, `external-csr`, `vault`, ...).
    fn provider_name(&self) -> &str;

    /// Which management modes this provider serves.
    fn supports(&self, mode: KeyManagementMode) -> bool;

    /// Generates (or idempotently returns) a managed key.
    async fn create_key(&self, request: CreateKey) -> Result<KeyRef>;

    /// Creates a CSR for the given identifiers with the referenced key.
    async fn create_csr(&self, request: CreateCsr) -> Result<CsrArtifact>;

    /// The public key of a managed key.
    async fn public_key(&self, key: &KeyRef) -> Result<PublicKeyInfo>;

    /// Exports a managed private key; `Ok(None)` when the key is not
    /// exportable or the authorization is insufficient.
    async fn export(
        &self,
        key: &KeyRef,
        authorization: &ExportAuthorization,
    ) -> Result<Option<SecretBytes>>;

    /// Destroys a key when no active/superseded version still references it.
    async fn destroy(&self, key: &KeyRef) -> Result<DestroyOutcome>;
}

/// Maps a policy algorithm to the rcgen key-pair generator label.
#[allow(dead_code)] // used by upcoming KMS/HSM providers (T10 follow-ups)
pub(crate) fn algorithm_name(algorithm: KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::EcP256 => "ECDSA_P256_SHA256",
        KeyAlgorithm::EcP384 => "ECDSA_P384_SHA384",
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => "RSA",
        KeyAlgorithm::Ed25519 => "ED25519",
    }
}

/// Generates a fresh key id scoped to a provider.
pub fn generate_key_id() -> KeyId {
    KeyId::generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_authorization_requires_key_export() {
        let authz = ExportAuthorization::key_export("admin", "manual backup");
        assert_eq!(authz.permission, "key.export");
        assert_eq!(authz.actor, "admin");
        let json = serde_json::to_string(&authz).unwrap();
        assert!(json.contains("key.export"));
    }

    #[test]
    fn algorithm_names_are_stable() {
        assert_eq!(algorithm_name(KeyAlgorithm::EcP256), "ECDSA_P256_SHA256");
        assert_eq!(algorithm_name(KeyAlgorithm::Ed25519), "ED25519");
    }
}
