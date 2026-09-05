//! Certificate key provider boundaries.
//!
//! The domain model stores [`KeyRef`] only. This module owns short-lived key
//! material access for managed keys and validates external CSRs without ever
//! importing their private keys.

use std::fmt;

use async_trait::async_trait;
use rcgen::{
    CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
    PKCS_RSA_SHA256, PKCS_RSA_SHA512, SanType,
};
use rustls::pki_types::CertificateSigningRequestDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::domain::{
    DnsIdentifier, Identifier, IdentifierSet, KeyAlgorithm, KeyId, KeyManagementMode, KeyPolicy,
    KeyRef,
};
use crate::error::{AcmeError, Result};
use crate::repository::FileSecretStore;

/// Secret bytes with redacted formatting and best-effort zeroization on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Creates a new secret wrapper.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrows the secret material for the current operation.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the raw bytes.
    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.0.len())
            .field("redacted", &true)
            .finish()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Request to create a managed key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateKey {
    /// Key lifecycle policy.
    pub policy: KeyPolicy,
    /// Optional caller-supplied external identifier.
    #[serde(default)]
    pub key_id: Option<KeyId>,
}

/// Request to create or validate a CSR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateCsr {
    /// Exact SAN set expected by the intent.
    pub identifiers: IdentifierSet,
    /// Desired key policy.
    pub policy: KeyPolicy,
    /// Existing key reference for managed reuse or external CSR proof.
    #[serde(default)]
    pub key_ref: Option<KeyRef>,
    /// Caller-supplied CSR for external mode.
    #[serde(default)]
    pub external_csr: Option<ExternalCsr>,
}

/// External CSR material supplied by the upstream owner.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalCsr {
    /// CSR bytes in DER form.
    pub csr_der: Vec<u8>,
}

impl fmt::Debug for ExternalCsr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalCsr")
            .field("der_len", &self.csr_der.len())
            .finish()
    }
}

impl ExternalCsr {
    /// Parses a PEM encoded external CSR.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let block = ::pem::parse(pem.as_bytes())
            .map_err(|err| AcmeError::pem(format!("parse CSR PEM: {err}")))?;
        if block.tag() != "CERTIFICATE REQUEST" {
            return Err(AcmeError::pem(format!(
                "expected CERTIFICATE REQUEST PEM, found {}",
                block.tag()
            )));
        }
        Ok(Self {
            csr_der: block.contents().to_vec(),
        })
    }
}

/// CSR returned by a provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsrArtifact {
    /// CSR DER bytes for ACME finalize.
    pub csr_der: Vec<u8>,
    /// Key reference bound to this CSR.
    pub key_ref: KeyRef,
    /// SANs validated or generated for this CSR.
    pub identifiers: IdentifierSet,
    /// Whether the private key is external to AcmeX.
    pub external: bool,
    /// SHA-256 fingerprint of the CSR subject public key.
    pub public_key_sha256: String,
}

/// Public key metadata safe to return through ordinary APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// Owning key reference.
    pub key_ref: KeyRef,
    /// SubjectPublicKeyInfo DER SHA-256.
    pub spki_sha256: String,
    /// SubjectPublicKeyInfo PEM.
    pub spki_pem: String,
}

/// Independent authorization required before exporting managed private keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportAuthorization {
    /// Actor that requested export.
    pub actor: String,
    /// Whether the actor has the high-privilege `key.export` grant.
    pub key_export_granted: bool,
    /// Human-readable audit reason.
    pub reason: String,
}

/// Result of a destroy request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestroyOutcome {
    /// Key material was destroyed.
    Destroyed,
    /// The key was already absent.
    NotFound,
    /// Policy or live references prevented destruction.
    Refused,
}

/// Explicit authorization required before destroying key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestroyAuthorization {
    /// Actor that requested destruction.
    pub actor: String,
    /// Whether the actor explicitly confirmed the irreversible destruction.
    pub confirmed: bool,
    /// Human-readable audit reason.
    pub reason: String,
}

/// Source of certificate keys and CSRs.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Creates a managed key.
    async fn create_key(&self, request: CreateKey) -> Result<KeyRef>;
    /// Creates a managed CSR or validates an external CSR.
    async fn create_csr(&self, request: CreateCsr) -> Result<CsrArtifact>;
    /// Returns non-secret public key metadata.
    async fn public_key(&self, key: &KeyRef) -> Result<PublicKeyInfo>;
    /// Exports private key bytes when policy and authorization both allow it.
    async fn export(
        &self,
        key: &KeyRef,
        authorization: ExportAuthorization,
    ) -> Result<Option<SecretBytes>>;
    /// Conservative destroy probe kept for compatibility: reports whether a
    /// key can be destroyed but never removes material. Real destruction
    /// goes through [`KeyProvider::destroy_confirmed`].
    async fn destroy(&self, key: &KeyRef) -> Result<DestroyOutcome>;
    /// Destroys key material after an explicit, auditable confirmation.
    ///
    /// The default preserves the conservative [`KeyProvider::destroy`]
    /// semantics so implementations that have not opted into confirmed
    /// destruction keep refusing.
    async fn destroy_confirmed(
        &self,
        key: &KeyRef,
        authorization: DestroyAuthorization,
    ) -> Result<DestroyOutcome> {
        let _ = authorization;
        self.destroy(key).await
    }
}

/// Software key provider backed by [`FileSecretStore`].
#[derive(Debug, Clone)]
pub struct SoftwareKeyProvider {
    provider_id: String,
    store: FileSecretStore,
}

impl SoftwareKeyProvider {
    /// Creates a software provider using a file secret store.
    pub fn new(store: FileSecretStore) -> Self {
        Self {
            provider_id: "software".to_string(),
            store,
        }
    }

    /// Creates a named software provider.
    pub fn with_provider_id(provider_id: impl Into<String>, store: FileSecretStore) -> Self {
        Self {
            provider_id: provider_id.into(),
            store,
        }
    }

    fn ensure_own_key(&self, key: &KeyRef) -> Result<()> {
        if key.provider != self.provider_id {
            return Err(AcmeError::invalid_input(format!(
                "key `{}` belongs to provider `{}`, not `{}`",
                key.key_id, key.provider, self.provider_id
            )));
        }
        Ok(())
    }

    async fn load_key_pair(&self, key: &KeyRef) -> Result<KeyPair> {
        self.ensure_own_key(key)?;
        let pem = self
            .store
            .get(key.key_id.as_str())
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("key `{}` not found", key.key_id)))?;
        let pem = String::from_utf8(pem)
            .map_err(|err| AcmeError::crypto(format!("stored key is not UTF-8 PEM: {err}")))?;
        KeyPair::from_pem(&pem)
            .map_err(|err| AcmeError::crypto(format!("parse stored private key: {err}")))
    }

    fn generate_key(algorithm: KeyAlgorithm) -> Result<KeyPair> {
        let result = match algorithm {
            KeyAlgorithm::EcP256 => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256),
            KeyAlgorithm::EcP384 => KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384),
            KeyAlgorithm::Ed25519 => KeyPair::generate_for(&PKCS_ED25519),
            KeyAlgorithm::Rsa2048 => KeyPair::generate_for(&PKCS_RSA_SHA256),
            KeyAlgorithm::Rsa4096 => KeyPair::generate_for(&PKCS_RSA_SHA512),
        };
        result.map_err(|err| AcmeError::crypto(format!("generate managed key: {err}")))
    }

    fn key_ref(&self, key_id: KeyId, policy: &KeyPolicy) -> KeyRef {
        KeyRef {
            provider: self.provider_id.clone(),
            key_id,
            algorithm: policy.algorithm,
            exportable: policy.exportable,
        }
    }
}

#[async_trait]
impl KeyProvider for SoftwareKeyProvider {
    async fn create_key(&self, request: CreateKey) -> Result<KeyRef> {
        if request.policy.mode != KeyManagementMode::Managed {
            return Err(AcmeError::invalid_input(
                "software provider can only create managed keys",
            ));
        }
        let key_id = request.key_id.unwrap_or_else(KeyId::generate);
        let key_ref = self.key_ref(key_id, &request.policy);
        let key_pair = Self::generate_key(request.policy.algorithm)?;
        self.store
            .put(key_ref.key_id.as_str(), key_pair.serialize_pem().as_bytes())
            .await?;
        Ok(key_ref)
    }

    async fn create_csr(&self, mut request: CreateCsr) -> Result<CsrArtifact> {
        if let Some(external) = request.external_csr.take() {
            return validate_external_csr(request, external);
        }

        if request.policy.mode != KeyManagementMode::Managed {
            return Err(AcmeError::invalid_input(
                "external CSR mode requires caller-provided CSR material",
            ));
        }

        let key_ref = match request.key_ref {
            Some(key_ref) => key_ref,
            None => {
                self.create_key(CreateKey {
                    policy: request.policy.clone(),
                    key_id: None,
                })
                .await?
            }
        };
        let key_pair = self.load_key_pair(&key_ref).await?;
        let params = certificate_params_for_identifiers(request.identifiers.as_slice())?;
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|err| AcmeError::crypto(format!("generate managed CSR: {err}")))?;
        let public_key_sha256 = spki_fingerprint_from_csr(csr.der())?;
        Ok(CsrArtifact {
            csr_der: csr.der().to_vec(),
            key_ref,
            identifiers: request.identifiers,
            external: false,
            public_key_sha256,
        })
    }

    async fn public_key(&self, key: &KeyRef) -> Result<PublicKeyInfo> {
        let pair = self.load_key_pair(key).await?;
        let pem = pair.public_key_pem();
        let block = ::pem::parse(pem.as_bytes())
            .map_err(|err| AcmeError::pem(format!("parse public key PEM: {err}")))?;
        let spki_sha256 = sha256_hex(block.contents());
        Ok(PublicKeyInfo {
            key_ref: key.clone(),
            spki_sha256,
            spki_pem: pem,
        })
    }

    async fn export(
        &self,
        key: &KeyRef,
        authorization: ExportAuthorization,
    ) -> Result<Option<SecretBytes>> {
        self.ensure_own_key(key)?;
        if !key.exportable || !authorization.key_export_granted {
            return Ok(None);
        }
        Ok(self
            .store
            .get(key.key_id.as_str())
            .await?
            .map(SecretBytes::new))
    }

    async fn destroy(&self, key: &KeyRef) -> Result<DestroyOutcome> {
        self.ensure_own_key(key)?;
        if self.store.contains(key.key_id.as_str()).await? {
            Ok(DestroyOutcome::Refused)
        } else {
            Ok(DestroyOutcome::NotFound)
        }
    }

    async fn destroy_confirmed(
        &self,
        key: &KeyRef,
        authorization: DestroyAuthorization,
    ) -> Result<DestroyOutcome> {
        self.ensure_own_key(key)?;
        if !authorization.confirmed {
            tracing::warn!(
                key_id = %key.key_id,
                actor = %authorization.actor,
                "key destroy refused: missing explicit confirmation"
            );
            return Ok(DestroyOutcome::Refused);
        }
        if !self.store.contains(key.key_id.as_str()).await? {
            return Ok(DestroyOutcome::NotFound);
        }
        if self.store.remove(key.key_id.as_str()).await? {
            tracing::info!(
                key_id = %key.key_id,
                actor = %authorization.actor,
                reason = %authorization.reason,
                "key material destroyed"
            );
            Ok(DestroyOutcome::Destroyed)
        } else {
            Ok(DestroyOutcome::NotFound)
        }
    }
}

fn validate_external_csr(request: CreateCsr, external: ExternalCsr) -> Result<CsrArtifact> {
    if request.policy.mode != KeyManagementMode::ExternalCsr {
        return Err(AcmeError::invalid_input(
            "external CSR material requires external_csr key policy",
        ));
    }
    let key_ref = request.key_ref.ok_or_else(|| {
        AcmeError::invalid_input("external CSR requires a caller-provided key_ref")
    })?;
    if key_ref.exportable || request.policy.exportable {
        return Err(AcmeError::invalid_input(
            "external CSR keys are never exportable",
        ));
    }

    let (_, csr) = X509CertificationRequest::from_der(&external.csr_der)
        .map_err(|err| AcmeError::crypto(format!("parse external CSR: {err}")))?;
    csr.verify_signature()
        .map_err(|err| AcmeError::crypto(format!("verify external CSR signature: {err}")))?;

    let mut actual = csr_identifiers(&csr)?;
    let mut expected = request.identifiers.as_slice().to_vec();
    actual.sort();
    actual.dedup();
    expected.sort();
    expected.dedup();
    if actual != expected {
        return Err(AcmeError::invalid_input(format!(
            "external CSR SAN mismatch: expected {:?}, found {:?}",
            expected, actual
        )));
    }

    let public_key_sha256 = sha256_hex(csr.certification_request_info.subject_pki.raw);
    Ok(CsrArtifact {
        csr_der: external.csr_der,
        key_ref,
        identifiers: request.identifiers,
        external: true,
        public_key_sha256,
    })
}

fn certificate_params_for_identifiers(identifiers: &[Identifier]) -> Result<CertificateParams> {
    if identifiers.is_empty() {
        return Err(AcmeError::invalid_input(
            "CSR requires at least one identifier",
        ));
    }
    let mut params = CertificateParams::default();
    params.subject_alt_names = san_types_for_identifiers(identifiers)?;
    Ok(params)
}

fn san_types_for_identifiers(identifiers: &[Identifier]) -> Result<Vec<SanType>> {
    identifiers
        .iter()
        .map(|identifier| match identifier {
            Identifier::Dns(dns) => dns
                .to_wire_value()
                .try_into()
                .map(SanType::DnsName)
                .map_err(|err| AcmeError::crypto(format!("invalid DNS SAN in CSR: {err}"))),
            Identifier::Ip(ip) => Ok(SanType::IpAddress(*ip)),
        })
        .collect()
}

fn csr_identifiers(csr: &X509CertificationRequest<'_>) -> Result<Vec<Identifier>> {
    let Some(extensions) = csr.requested_extensions() else {
        return Ok(Vec::new());
    };
    let mut identifiers = Vec::new();
    for extension in extensions {
        if let ParsedExtension::SubjectAlternativeName(san) = extension {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(domain) => {
                        identifiers.push(Identifier::try_dns(*domain).unwrap_or_else(|_| {
                            Identifier::Dns(DnsIdentifier::parse_lenient(domain))
                        }))
                    }
                    GeneralName::IPAddress(bytes) => {
                        let ip = match *bytes {
                            [a, b, c, d] => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                *a, *b, *c, *d,
                            ))),
                            bytes if bytes.len() == 16 => {
                                let mut octets = [0_u8; 16];
                                octets.copy_from_slice(bytes);
                                Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
                            }
                            _ => None,
                        };
                        if let Some(ip) = ip {
                            identifiers.push(Identifier::Ip(ip));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(identifiers)
}

fn spki_fingerprint_from_csr(csr_der: &CertificateSigningRequestDer<'_>) -> Result<String> {
    let (_, csr) = X509CertificationRequest::from_der(csr_der.as_ref())
        .map_err(|err| AcmeError::crypto(format!("parse generated CSR: {err}")))?;
    Ok(sha256_hex(csr.certification_request_info.subject_pki.raw))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn confirmed(actor: &str) -> DestroyAuthorization {
        DestroyAuthorization {
            actor: actor.to_string(),
            confirmed: true,
            reason: "rotation cleanup".to_string(),
        }
    }

    fn unconfirmed() -> DestroyAuthorization {
        DestroyAuthorization {
            actor: "test".to_string(),
            confirmed: false,
            reason: "confirmation missing".to_string(),
        }
    }

    fn export_authorization() -> ExportAuthorization {
        ExportAuthorization {
            actor: "test".to_string(),
            key_export_granted: true,
            reason: "key lifecycle test".to_string(),
        }
    }

    struct TempDirGuard(PathBuf);

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // A tiny temp-dir helper so tests do not need a `tempfile` dependency.
    fn temp_store_dir(tag: &str) -> TempDirGuard {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "acmex-key-test-{tag}-{}-{}",
            std::process::id(),
            unique
        ));
        std::fs::create_dir_all(&path).expect("temp dir create");
        TempDirGuard(path)
    }

    fn exportable_policy() -> KeyPolicy {
        KeyPolicy {
            exportable: true,
            ..KeyPolicy::default()
        }
    }

    #[tokio::test]
    async fn destroy_confirmed_removes_key_material() {
        let dir = temp_store_dir("destroy");
        let provider = SoftwareKeyProvider::new(FileSecretStore::new(dir.0.join("secrets")));
        let key = provider
            .create_key(CreateKey {
                policy: exportable_policy(),
                key_id: None,
            })
            .await
            .unwrap();

        // Unconfirmed requests are refused and keep the key intact.
        let refused = provider
            .destroy_confirmed(&key, unconfirmed())
            .await
            .unwrap();
        assert_eq!(refused, DestroyOutcome::Refused);
        assert!(
            provider
                .export(&key, export_authorization())
                .await
                .unwrap()
                .is_some()
        );

        // Confirmed destruction removes the material.
        let destroyed = provider
            .destroy_confirmed(&key, confirmed("security-team"))
            .await
            .unwrap();
        assert_eq!(destroyed, DestroyOutcome::Destroyed);

        // The key is gone: export yields nothing and public key lookup is
        // a classified NotFound, never silent success.
        assert!(
            provider
                .export(&key, export_authorization())
                .await
                .unwrap()
                .is_none()
        );
        let public = provider.public_key(&key).await;
        assert!(matches!(public, Err(AcmeError::NotFound(_))));

        // Destroying again reports NotFound instead of pretending.
        let again = provider
            .destroy_confirmed(&key, confirmed("security-team"))
            .await
            .unwrap();
        assert_eq!(again, DestroyOutcome::NotFound);
    }

    #[tokio::test]
    async fn unconfirmed_destroy_is_refused_without_touching_the_key() {
        let dir = temp_store_dir("unconfirmed");
        let provider = SoftwareKeyProvider::new(FileSecretStore::new(dir.0.join("secrets")));
        let key = provider
            .create_key(CreateKey {
                policy: exportable_policy(),
                key_id: None,
            })
            .await
            .unwrap();

        let outcome = provider
            .destroy_confirmed(&key, unconfirmed())
            .await
            .unwrap();
        assert_eq!(outcome, DestroyOutcome::Refused);
        // The key pair still produces CSRs after the refused destroy.
        let identifiers = IdentifierSet::parse(["destroy.example.com"]).unwrap();
        let csr = provider
            .create_csr(CreateCsr {
                identifiers,
                policy: exportable_policy(),
                key_ref: Some(key.clone()),
                external_csr: None,
            })
            .await
            .unwrap();
        assert!(!csr.csr_der.is_empty());
    }
}
