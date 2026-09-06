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

/// AWS KMS-backed key provider (feature `kms-aws`).
#[cfg(feature = "kms-aws")]
pub mod kms;
#[cfg(feature = "kms-aws")]
pub use kms::{KmsKeyProvider, KmsKeyProviderConfig};

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

/// Provider id used by [`KeyRef`]s that describe caller-held external key
/// material (`external_csr` mode). No secret-store entry ever exists behind
/// such a reference.
pub const EXTERNAL_CSR_KEY_PROVIDER: &str = "external";

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
    ///
    /// Strict single-document parsing: `pem::parse` alone would skip leading
    /// garbage and silently pick the first block out of a multi-document
    /// paste, which makes "certificate chain pasted instead of CSR"
    /// indistinguishable from a valid submission.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let blocks = ::pem::parse_many(pem.as_bytes())
            .map_err(|err| AcmeError::pem(format!("parse CSR PEM: {err}")))?;
        if blocks.len() != 1 {
            return Err(AcmeError::pem(format!(
                "expected exactly one PEM block, found {}",
                blocks.len()
            )));
        }
        let block = &blocks[0];
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

    // Algorithm agreement is checked before the signature: an unsupported or
    // misdeclared key is rejected with the exact expected/actual pair, which
    // stays clearer than a cryptographic verification error on a key AcmeX
    // could never use anyway.
    let csr_algorithm = csr_key_algorithm(&csr)?;
    if csr_algorithm != request.policy.algorithm {
        return Err(AcmeError::crypto(format!(
            "external CSR key algorithm mismatch: policy declares {:?} but the CSR public key is {:?}",
            request.policy.algorithm, csr_algorithm
        )));
    }

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

/// Derives the [`KeyAlgorithm`] from a CSR's SubjectPublicKeyInfo.
///
/// OID mapping (SPKI `algorithm` → [`KeyAlgorithm`]):
///
/// | SPKI algorithm OID | curve / modulus | KeyAlgorithm |
/// |--------------------|-----------------|--------------|
/// | `rsaEncryption` (1.2.840.113549.1.1.1) | 2048-bit modulus | `Rsa2048` |
/// | `rsaEncryption` (1.2.840.113549.1.1.1) | 4096-bit modulus | `Rsa4096` |
/// | `rsaEncryption` (1.2.840.113549.1.1.1) | any other modulus (incl. < 2048-bit) | rejected, naming the modulus length |
/// | `id-ecPublicKey` (1.2.840.10045.2.1) | `prime256v1` (1.2.840.10045.3.1.7) | `EcP256` |
/// | `id-ecPublicKey` (1.2.840.10045.2.1) | `secp384r1` (1.3.132.0.34) | `EcP384` |
/// | `id-ecPublicKey` (1.2.840.10045.2.1) | `secp521r1` (1.3.132.0.35) | rejected (no key algorithm) |
/// | Ed25519 (1.3.101.112) | — | `Ed25519` |
///
/// This doubles as the minimum-strength gate for external CSRs: RSA keys
/// below 2048 bits (or any unclassified modulus size) are refused with the
/// actual modulus length instead of being accepted under a wrong label.
pub(crate) fn csr_key_algorithm(csr: &X509CertificationRequest<'_>) -> Result<KeyAlgorithm> {
    use x509_parser::oid_registry::{
        OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_NIST_EC_P521,
        OID_PKCS1_RSAENCRYPTION, OID_SIG_ED25519,
    };
    let spki = &csr.certification_request_info.subject_pki;
    if spki.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION {
        let bits = crate::crypto::keypair::der::rsa_public_key_modulus_octets(
            spki.subject_public_key.data.as_ref(),
        )
        .map(|octets| octets.saturating_mul(8))
        .ok_or_else(|| {
            AcmeError::crypto("parse external CSR RSA public key (malformed RSAPublicKey)")
        })?;
        return match bits {
            2048 => Ok(KeyAlgorithm::Rsa2048),
            4096 => Ok(KeyAlgorithm::Rsa4096),
            _ => Err(AcmeError::crypto(format!(
                "external CSR RSA key has a {bits}-bit modulus; \
                 only 2048 and 4096 are supported"
            ))),
        };
    }
    if spki.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .ok_or_else(|| AcmeError::crypto("external CSR EC key has no named-curve parameter"))?;
        return if curve == OID_EC_P256 {
            Ok(KeyAlgorithm::EcP256)
        } else if curve == OID_NIST_EC_P384 {
            Ok(KeyAlgorithm::EcP384)
        } else if curve == OID_NIST_EC_P521 {
            Err(AcmeError::crypto(
                "external CSR EC key uses P-521 (secp521r1), which is not a supported \
                 certificate key algorithm",
            ))
        } else {
            Err(AcmeError::crypto(format!(
                "external CSR EC key uses unsupported curve OID {curve}"
            )))
        };
    }
    if spki.algorithm.algorithm == OID_SIG_ED25519 {
        return Ok(KeyAlgorithm::Ed25519);
    }
    Err(AcmeError::crypto(format!(
        "external CSR public key algorithm {} is not supported",
        spki.algorithm.algorithm
    )))
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

    /// An external-mode [`KeyRef`] describing caller-held key material.
    fn external_ref(algorithm: KeyAlgorithm) -> KeyRef {
        KeyRef {
            provider: "external".to_string(),
            key_id: crate::domain::KeyId::new("key_external_test").unwrap(),
            algorithm,
            exportable: false,
        }
    }

    /// Generates an external key pair of `algorithm` and its PKCS#10 CSR
    /// (DER) for `example.com`, exactly like an upstream key holder would.
    fn external_key_and_csr_der(algorithm: KeyAlgorithm) -> (rcgen::KeyPair, Vec<u8>) {
        let key = match algorithm {
            KeyAlgorithm::EcP256 => rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            KeyAlgorithm::EcP384 => rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384),
            KeyAlgorithm::Ed25519 => rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519),
            KeyAlgorithm::Rsa2048 => {
                rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
            }
            KeyAlgorithm::Rsa4096 => {
                rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_4096)
            }
        }
        .unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let der = params
            .serialize_request(&key)
            .unwrap()
            .der()
            .as_ref()
            .to_vec();
        (key, der)
    }

    /// Runs the external-CSR validation through the provider, the same path
    /// the CreateCsr workflow step uses.
    async fn validate_external(
        policy_algorithm: KeyAlgorithm,
        csr_der: Vec<u8>,
    ) -> Result<CsrArtifact> {
        let dir = temp_store_dir("external-csr");
        let provider = SoftwareKeyProvider::new(FileSecretStore::new(dir.0.join("secrets")));
        provider
            .create_csr(CreateCsr {
                identifiers: IdentifierSet::parse(["example.com"]).unwrap(),
                policy: KeyPolicy {
                    algorithm: policy_algorithm,
                    mode: KeyManagementMode::ExternalCsr,
                    ..KeyPolicy::default()
                },
                key_ref: Some(external_ref(policy_algorithm)),
                external_csr: Some(ExternalCsr { csr_der }),
            })
            .await
    }

    #[test]
    fn csr_key_algorithm_derives_every_supported_algorithm() {
        for (algorithm, expected) in [
            (KeyAlgorithm::EcP256, KeyAlgorithm::EcP256),
            (KeyAlgorithm::EcP384, KeyAlgorithm::EcP384),
            (KeyAlgorithm::Ed25519, KeyAlgorithm::Ed25519),
            (KeyAlgorithm::Rsa2048, KeyAlgorithm::Rsa2048),
            (KeyAlgorithm::Rsa4096, KeyAlgorithm::Rsa4096),
        ] {
            let (_key, csr_der) = external_key_and_csr_der(algorithm);
            let (_, csr) = X509CertificationRequest::from_der(&csr_der).unwrap();
            assert_eq!(
                csr_key_algorithm(&csr).unwrap(),
                expected,
                "SPKI derivation for {algorithm:?}"
            );
        }
    }

    #[tokio::test]
    async fn external_csr_with_matching_policy_algorithm_is_accepted() {
        for algorithm in [
            KeyAlgorithm::EcP256,
            KeyAlgorithm::EcP384,
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::Rsa2048,
            KeyAlgorithm::Rsa4096,
        ] {
            let (_key, csr_der) = external_key_and_csr_der(algorithm);
            let artifact = validate_external(algorithm, csr_der).await.unwrap();
            assert!(artifact.external, "external CSR must stay external");
            assert_eq!(artifact.key_ref.algorithm, algorithm);
        }
    }

    #[tokio::test]
    async fn external_csr_with_mismatched_policy_algorithm_is_rejected() {
        let (_key, csr_der) = external_key_and_csr_der(KeyAlgorithm::EcP256);
        let err = validate_external(KeyAlgorithm::Rsa2048, csr_der)
            .await
            .unwrap_err();
        assert!(matches!(err, AcmeError::Crypto(_)), "got: {err:?}");
        let message = err.to_string();
        assert!(
            message.contains("algorithm mismatch"),
            "error must name the mismatch: {message}"
        );
        assert!(
            message.contains("Rsa2048") && message.contains("EcP256"),
            "error must name the declared and the actual algorithm: {message}"
        );
    }

    #[tokio::test]
    async fn external_csr_with_unsupported_algorithm_is_rejected() {
        // P-521 has no KeyAlgorithm variant: rcgen can generate the CSR, but
        // AcmeX must refuse it instead of labeling it with the policy value.
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512).unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let csr_der = params
            .serialize_request(&key)
            .unwrap()
            .der()
            .as_ref()
            .to_vec();
        let err = validate_external(KeyAlgorithm::EcP256, csr_der)
            .await
            .unwrap_err();
        assert!(matches!(err, AcmeError::Crypto(_)), "got: {err:?}");
        assert!(
            err.to_string().contains("P-521"),
            "error must name the unsupported algorithm: {err}"
        );
    }
}
