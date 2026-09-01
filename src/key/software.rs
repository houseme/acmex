//! Software key provider: managed keys in a permission-guarded secret store.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;

use rcgen::{CertificateParams, KeyPair, SanType};

use crate::dns::spec::SecretBytes;
use crate::domain::{Identifier, KeyAlgorithm, KeyId, KeyManagementMode, KeyPolicy, KeyRef};
use crate::error::{AcmeError, Result};
use crate::repository::secret_store::FileSecretStore;

use super::{
    CreateCsr, CreateKey, CsrArtifact, DestroyOutcome, ExportAuthorization, KeyProvider,
    PublicKeyInfo,
};

/// Software-managed keys: generated in-process, persisted (PEM) under
/// restrictive permissions via [`FileSecretStore`].
pub struct SoftwareKeyProvider {
    secrets: Arc<FileSecretStore>,
}

impl SoftwareKeyProvider {
    /// A provider storing keys in the given secret store.
    pub fn new(secrets: Arc<FileSecretStore>) -> Self {
        Self { secrets }
    }

    /// A provider rooted at a directory (creates `<root>` with 0700).
    pub fn with_root(root: impl Into<std::path::PathBuf>) -> Self {
        Self::new(Arc::new(FileSecretStore::new(root)))
    }

    /// Generates a key pair for the algorithm (Ed25519 and P-256 supported
    /// by rcgen; RSA requests are rejected with an explicit error).
    fn generate_pair(policy: &KeyPolicy) -> Result<KeyPair> {
        match policy.algorithm {
            KeyAlgorithm::Ed25519 => KeyPair::generate(),
            KeyAlgorithm::EcP256 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            other => {
                return Err(AcmeError::crypto(format!(
                    "software key provider cannot generate {other:?} keys yet; \
                     use Ed25519 or EcP256"
                )));
            }
        }
        .map_err(|e| AcmeError::crypto(format!("key generation failed: {e}")))
    }

    fn store_id(key_id: &KeyId) -> String {
        format!("key_{}", key_id.as_str().trim_start_matches("key_"))
    }

    async fn load_pair(&self, key: &KeyRef) -> Result<KeyPair> {
        if key.provider != self.provider_name() {
            return Err(AcmeError::InvalidInput(format!(
                "key `{}` belongs to provider `{}`, not `{}`",
                key.key_id,
                key.provider,
                self.provider_name()
            )));
        }
        let bytes = self
            .secrets
            .get(&Self::store_id(&key.key_id))
            .await?
            .ok_or_else(|| {
                AcmeError::NotFound(format!(
                    "managed key `{}` not found in the secret store",
                    key.key_id
                ))
            })?;
        let pem = std::str::from_utf8(&bytes)
            .map_err(|_| AcmeError::crypto("stored key is not valid UTF-8 PEM".to_string()))?;
        KeyPair::from_pem(pem).map_err(|e| AcmeError::crypto(format!("stored key invalid: {e}")))
    }

    fn key_ref(key_id: KeyId, policy: &KeyPolicy) -> KeyRef {
        KeyRef {
            provider: "software".to_string(),
            key_id,
            algorithm: policy.algorithm,
            exportable: policy.exportable,
        }
    }
}

#[async_trait]
impl KeyProvider for SoftwareKeyProvider {
    fn provider_name(&self) -> &str {
        "software"
    }

    fn supports(&self, mode: KeyManagementMode) -> bool {
        mode == KeyManagementMode::Managed
    }

    async fn create_key(&self, request: CreateKey) -> Result<KeyRef> {
        let key_id = match &request.idempotency_key {
            Some(idempotency) => {
                let scoped = format!("key_{}", idempotency.trim_start_matches("key_"));
                KeyId::new(scoped)?
            }
            None => super::generate_key_id(),
        };
        // Idempotency: an existing stored key is returned as-is.
        if self.secrets.contains(&Self::store_id(&key_id)).await? {
            return Ok(Self::key_ref(key_id, &request.policy));
        }

        let pair = Self::generate_pair(&request.policy)?;
        self.secrets
            .put(&Self::store_id(&key_id), pair.serialize_pem().as_bytes())
            .await?;
        Ok(Self::key_ref(key_id, &request.policy))
    }

    async fn create_csr(&self, request: CreateCsr) -> Result<CsrArtifact> {
        let pair = self.load_pair(&request.key).await?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| AcmeError::crypto(format!("csr params failed: {e}")))?;
        for identifier in &request.identifiers {
            let san = match identifier {
                Identifier::Dns(name) => SanType::DnsName(
                    name.to_wire_value()
                        .try_into()
                        .map_err(|e| AcmeError::InvalidInput(format!("invalid DNS SAN: {e}")))?,
                ),
                Identifier::Ip(addr) => SanType::IpAddress(*addr),
            };
            params.subject_alt_names.push(san);
        }
        let csr = params
            .serialize_request(&pair)
            .map_err(|e| AcmeError::crypto(format!("csr serialization failed: {e}")))?;
        let pem = csr
            .pem()
            .map_err(|e| AcmeError::crypto(format!("csr PEM encoding failed: {e}")))?;
        Ok(CsrArtifact {
            der: csr.der().to_vec(),
            pem,
        })
    }

    async fn public_key(&self, key: &KeyRef) -> Result<PublicKeyInfo> {
        let pair = self.load_pair(key).await?;
        let public_der = pair.public_key_raw();
        let spki_der = wrap_spki(public_der, key.algorithm);
        let pem = pem_encode("PUBLIC KEY", &spki_der);
        Ok(PublicKeyInfo {
            pem,
            algorithm: key.algorithm,
        })
    }

    async fn export(
        &self,
        key: &KeyRef,
        authorization: &ExportAuthorization,
    ) -> Result<Option<SecretBytes>> {
        if authorization.permission != "key.export" {
            tracing::warn!(
                actor = authorization.actor,
                "key export attempted without key.export permission"
            );
            return Ok(None);
        }
        if !key.exportable {
            tracing::warn!(
                key = key.key_id.as_str(),
                actor = authorization.actor,
                "export refused: key is not exportable"
            );
            return Ok(None);
        }
        let bytes = self
            .secrets
            .get(&Self::store_id(&key.key_id))
            .await?
            .ok_or_else(|| {
                AcmeError::NotFound(format!("managed key `{}` not found", key.key_id))
            })?;
        tracing::info!(
            key = key.key_id.as_str(),
            actor = authorization.actor,
            purpose = authorization.purpose,
            "managed key exported (audited)"
        );
        Ok(Some(SecretBytes::new(bytes)))
    }

    async fn destroy(&self, key: &KeyRef) -> Result<DestroyOutcome> {
        // Callers (application service) must check version references; the
        // store itself only refuses unknown ids.
        if !self.secrets.contains(&Self::store_id(&key.key_id)).await? {
            return Ok(DestroyOutcome::NotFound);
        }
        let removed = self.secrets.remove(&Self::store_id(&key.key_id)).await?;
        Ok(if removed {
            DestroyOutcome::Destroyed
        } else {
            DestroyOutcome::NotFound
        })
    }
}

/// Minimal SPKI wrapper: raw public key bytes → SubjectPublicKeyInfo DER.
fn wrap_spki(raw: &[u8], algorithm: KeyAlgorithm) -> Vec<u8> {
    let (oid, parameters): (&[u8], &[u8]) = match algorithm {
        KeyAlgorithm::Ed25519 => (&[0x2b, 0x65, 0x70], &[0x05, 0x00]), // 1.3.101.112 NULL
        KeyAlgorithm::EcP256 => (
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], // 1.2.840.10045.2.1
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], // P-256 OID
        ),
        _ => (
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
            &[0x05, 0x00],
        ),
    };
    let mut algorithm_identifier = vec![0x30];
    let inner_len = oid.len() + 2 + parameters.len();
    algorithm_identifier.push(inner_len as u8);
    algorithm_identifier.push(0x06);
    algorithm_identifier.push(oid.len() as u8);
    algorithm_identifier.extend_from_slice(oid);
    algorithm_identifier.extend_from_slice(parameters);

    let mut spki = vec![0x30];
    let total = algorithm_identifier.len() + 2 + raw.len();
    if total < 128 {
        spki.push(total as u8);
    } else {
        spki.push(0x81);
        spki.push(total as u8);
    }
    spki.extend_from_slice(&algorithm_identifier);
    spki.push(0x03);
    spki.push((raw.len() + 1) as u8);
    spki.push(0x00); // no unused bits
    spki.extend_from_slice(raw);
    spki
}

fn pem_encode(tag: &str, der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {tag}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {tag}-----\n"));
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::Clock;

    fn store() -> Arc<FileSecretStore> {
        let dir = std::env::temp_dir().join(format!(
            "acmex-swkey-{}-{}",
            std::process::id(),
            crate::repository::SystemClock.now().as_millisecond()
        ));
        Arc::new(FileSecretStore::new(dir))
    }

    #[tokio::test]
    async fn managed_key_lifecycle() {
        let provider = SoftwareKeyProvider::new(store());
        let policy = KeyPolicy {
            algorithm: KeyAlgorithm::Ed25519,
            mode: KeyManagementMode::Managed,
            rotation: Default::default(),
            exportable: true,
        };
        let key_ref = provider
            .create_key(CreateKey::new(policy.clone()))
            .await
            .unwrap();
        assert_eq!(key_ref.provider, "software");
        assert!(key_ref.exportable);

        // CSR with DNS + IP SANs.
        let csr = provider
            .create_csr(CreateCsr {
                key: key_ref.clone(),
                identifiers: vec![
                    Identifier::try_dns("example.com").unwrap(),
                    Identifier::try_ip("192.0.2.1").unwrap(),
                ],
            })
            .await
            .unwrap();
        assert!(!csr.der.is_empty());
        assert!(csr.pem.contains("BEGIN CERTIFICATE REQUEST"));

        // Public key parses back.
        let public = provider.public_key(&key_ref).await.unwrap();
        assert!(public.pem.contains("BEGIN PUBLIC KEY"));

        // Authorized export works; unauthorized returns None.
        let exported = provider
            .export(
                &key_ref,
                &ExportAuthorization::key_export("admin", "backup"),
            )
            .await
            .unwrap()
            .expect("exportable key exports with permission");
        assert!(
            std::str::from_utf8(exported.expose())
                .unwrap()
                .contains("PRIVATE KEY")
        );
        let denied = provider
            .export(
                &key_ref,
                &ExportAuthorization {
                    actor: "intern".to_string(),
                    purpose: "curiosity".to_string(),
                    permission: "cert.read".to_string(),
                },
            )
            .await
            .unwrap();
        assert!(denied.is_none());

        // Idempotent create with an explicit key yields the same reference.
        let a = provider
            .create_key(CreateKey {
                policy: policy.clone(),
                idempotency_key: Some("fixed".to_string()),
            })
            .await
            .unwrap();
        let b = provider
            .create_key(CreateKey {
                policy,
                idempotency_key: Some("fixed".to_string()),
            })
            .await
            .unwrap();
        assert_eq!(a.key_id, b.key_id);

        // Destroy.
        assert_eq!(
            provider.destroy(&key_ref).await.unwrap(),
            DestroyOutcome::Destroyed
        );
        assert_eq!(
            provider.destroy(&key_ref).await.unwrap(),
            DestroyOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn non_exportable_keys_refuse_export() {
        let provider = SoftwareKeyProvider::new(store());
        let policy = KeyPolicy::default(); // exportable: false
        let key_ref = provider.create_key(CreateKey::new(policy)).await.unwrap();
        let exported = provider
            .export(&key_ref, &ExportAuthorization::key_export("admin", "test"))
            .await
            .unwrap();
        assert!(exported.is_none(), "non-exportable keys never export");
    }

    #[tokio::test]
    async fn unsupported_algorithm_is_explicit() {
        let provider = SoftwareKeyProvider::new(store());
        let policy = KeyPolicy {
            algorithm: KeyAlgorithm::Rsa4096,
            mode: KeyManagementMode::Managed,
            rotation: Default::default(),
            exportable: false,
        };
        let err = provider
            .create_key(CreateKey::new(policy))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cannot generate"));
    }
}
