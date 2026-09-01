use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use acmex::{
    CreateCsr, CreateKey, ExportAuthorization, ExternalCsr, IdentifierSet, KeyAlgorithm, KeyId,
    KeyManagementMode, KeyPolicy, KeyProvider, KeyRef, SoftwareKeyProvider,
    repository::FileSecretStore,
};
use rcgen::{CertificateParams, KeyPair};

#[tokio::test]
async fn key_provider_managed_key_creates_csr_and_public_key() {
    let provider = SoftwareKeyProvider::new(FileSecretStore::new(temp_dir("managed-key")));
    let policy = KeyPolicy {
        algorithm: KeyAlgorithm::EcP256,
        mode: KeyManagementMode::Managed,
        rotation: Default::default(),
        exportable: false,
    };

    let key_ref = provider
        .create_key(CreateKey {
            policy: policy.clone(),
            key_id: Some(KeyId::new("key_contract").unwrap()),
        })
        .await
        .unwrap();
    let artifact = provider
        .create_csr(CreateCsr {
            identifiers: IdentifierSet::parse(["example.com", "192.0.2.10"]).unwrap(),
            policy,
            key_ref: Some(key_ref.clone()),
            external_csr: None,
        })
        .await
        .unwrap();
    let public_key = provider.public_key(&key_ref).await.unwrap();

    assert!(!artifact.csr_der.is_empty());
    assert_eq!(artifact.key_ref, key_ref);
    assert_eq!(artifact.public_key_sha256, public_key.spki_sha256);
    assert!(!artifact.external);
}

#[tokio::test]
async fn key_provider_non_exportable_key_refuses_export_without_leaking_secret() {
    let provider = SoftwareKeyProvider::new(FileSecretStore::new(temp_dir("non-exportable")));
    let key_ref = provider
        .create_key(CreateKey {
            policy: KeyPolicy::default(),
            key_id: None,
        })
        .await
        .unwrap();

    let exported = provider
        .export(
            &key_ref,
            ExportAuthorization {
                actor: "operator".into(),
                key_export_granted: true,
                reason: "contract-test".into(),
            },
        )
        .await
        .unwrap();

    assert!(exported.is_none());
}

#[tokio::test]
async fn key_provider_exportable_key_requires_authorization() {
    let provider = SoftwareKeyProvider::new(FileSecretStore::new(temp_dir("exportable")));
    let policy = KeyPolicy {
        exportable: true,
        ..KeyPolicy::default()
    };
    let key_ref = provider
        .create_key(CreateKey {
            policy,
            key_id: None,
        })
        .await
        .unwrap();

    let denied = provider
        .export(
            &key_ref,
            ExportAuthorization {
                actor: "viewer".into(),
                key_export_granted: false,
                reason: "missing grant".into(),
            },
        )
        .await
        .unwrap();
    let allowed = provider
        .export(
            &key_ref,
            ExportAuthorization {
                actor: "admin".into(),
                key_export_granted: true,
                reason: "break-glass".into(),
            },
        )
        .await
        .unwrap();

    assert!(denied.is_none());
    let secret = allowed.unwrap();
    assert!(
        std::str::from_utf8(secret.expose_secret())
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
    assert!(!format!("{secret:?}").contains("BEGIN PRIVATE KEY"));
}

#[tokio::test]
async fn external_csr_validates_signature_and_exact_sans() {
    let provider = SoftwareKeyProvider::new(FileSecretStore::new(temp_dir("external-csr")));
    let identifiers = IdentifierSet::parse(["example.com", "www.example.com"]).unwrap();
    let csr = signed_csr(&identifiers);
    let key_ref = KeyRef {
        provider: "external-hsm".into(),
        key_id: KeyId::new("key_external").unwrap(),
        algorithm: KeyAlgorithm::EcP256,
        exportable: false,
    };

    let artifact = provider
        .create_csr(CreateCsr {
            identifiers: identifiers.clone(),
            policy: KeyPolicy {
                mode: KeyManagementMode::ExternalCsr,
                ..KeyPolicy::default()
            },
            key_ref: Some(key_ref.clone()),
            external_csr: Some(ExternalCsr { csr_der: csr }),
        })
        .await
        .unwrap();

    assert!(artifact.external);
    assert_eq!(artifact.key_ref, key_ref);
    assert_eq!(artifact.identifiers, identifiers);
}

#[tokio::test]
async fn external_csr_rejects_san_mismatch() {
    let provider = SoftwareKeyProvider::new(FileSecretStore::new(temp_dir("external-mismatch")));
    let csr = signed_csr(&IdentifierSet::parse(["example.com"]).unwrap());

    let result = provider
        .create_csr(CreateCsr {
            identifiers: IdentifierSet::parse(["other.example.com"]).unwrap(),
            policy: KeyPolicy {
                mode: KeyManagementMode::ExternalCsr,
                ..KeyPolicy::default()
            },
            key_ref: Some(KeyRef {
                provider: "external-hsm".into(),
                key_id: KeyId::new("key_external_mismatch").unwrap(),
                algorithm: KeyAlgorithm::EcP256,
                exportable: false,
            }),
            external_csr: Some(ExternalCsr { csr_der: csr }),
        })
        .await;

    assert!(result.is_err());
}

fn signed_csr(identifiers: &IdentifierSet) -> Vec<u8> {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = identifiers
        .iter()
        .map(|identifier| match identifier {
            acmex::domain::Identifier::Dns(dns) => dns
                .to_wire_value()
                .try_into()
                .map(rcgen::SanType::DnsName)
                .unwrap(),
            acmex::domain::Identifier::Ip(ip) => rcgen::SanType::IpAddress(*ip),
        })
        .collect();
    params.serialize_request(&key).unwrap().der().to_vec()
}

fn temp_dir(name: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "acmex-t10-key-provider-{name}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
