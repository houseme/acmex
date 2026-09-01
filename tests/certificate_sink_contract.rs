use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use acmex::{
    CertificateMaterialBuilder, CertificateMaterialRef, CertificateSink, CertificateVersion,
    CleanupOutcome, DeliveryRequirement, DeliveryTargetKind, DeploymentHealth, DeploymentSpec,
    FakeAgentCertificateSink, FileCertificateSink, IdentifierSet, KeyAlgorithm, KeyId, KeyRef,
    LineageId, SecretBytes, TargetId, VersionId, VersionState,
};

#[tokio::test]
async fn material_builder_verifies_private_key_matches_certificate() {
    let (version, private_key) = sample_version("example.com");
    let material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&version, Some(SecretBytes::new(private_key)))
        .unwrap();

    assert_eq!(material.fullchain_pem, version.certificate_chain_pem);
    assert!(material.private_key_pem.is_some());
}

#[tokio::test]
async fn file_sink_stages_without_changing_current_then_activates_and_rolls_back() {
    let root = temp_dir("file-sink");
    let sink = FileCertificateSink::new();
    let spec = DeploymentSpec {
        target_id: TargetId::new("web").unwrap(),
        kind: DeliveryTargetKind::File,
        reference: root.to_string_lossy().into_owned(),
        requirement: DeliveryRequirement::Required,
    };
    let (old_version, old_key) = sample_version("old.example.com");
    let (new_version, new_key) = sample_version("new.example.com");
    let old_material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&old_version, Some(SecretBytes::new(old_key)))
        .unwrap();
    let new_material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&new_version, Some(SecretBytes::new(new_key)))
        .unwrap();

    let old_staged = sink
        .stage(
            &spec,
            &old_version,
            CertificateMaterialRef {
                material: &old_material,
            },
        )
        .await
        .unwrap();
    sink.activate(&old_staged).await.unwrap();
    assert_eq!(
        sink.health_check(&old_staged).await.unwrap(),
        DeploymentHealth::Healthy
    );

    let current_before = std::fs::read_link(root.join("current")).unwrap();
    let new_staged = sink
        .stage(
            &spec,
            &new_version,
            CertificateMaterialRef {
                material: &new_material,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(root.join("current")).unwrap(),
        current_before
    );

    sink.activate(&new_staged).await.unwrap();
    assert_eq!(
        sink.health_check(&new_staged).await.unwrap(),
        DeploymentHealth::Healthy
    );
    sink.rollback(&new_staged).await.unwrap();
    assert_eq!(
        sink.health_check(&old_staged).await.unwrap(),
        DeploymentHealth::Healthy
    );
}

#[tokio::test]
async fn file_sink_cleanup_is_idempotent() {
    let root = temp_dir("file-cleanup");
    let sink = FileCertificateSink::new();
    let spec = DeploymentSpec {
        target_id: TargetId::new("web").unwrap(),
        kind: DeliveryTargetKind::File,
        reference: root.to_string_lossy().into_owned(),
        requirement: DeliveryRequirement::Required,
    };
    let (version, private_key) = sample_version("cleanup.example.com");
    let material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&version, Some(SecretBytes::new(private_key)))
        .unwrap();
    let staged = sink
        .stage(
            &spec,
            &version,
            CertificateMaterialRef {
                material: &material,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        sink.cleanup(&staged).await.unwrap(),
        CleanupOutcome::Cleaned
    );
    assert_eq!(
        sink.cleanup(&staged).await.unwrap(),
        CleanupOutcome::AlreadyClean
    );
}

#[tokio::test]
async fn fake_agent_sink_contract_covers_cas_health_rollback_and_cleanup() {
    let sink = FakeAgentCertificateSink::new();
    let spec = DeploymentSpec {
        target_id: TargetId::new("agent").unwrap(),
        kind: DeliveryTargetKind::Webhook,
        reference: "edge-agent-a".into(),
        requirement: DeliveryRequirement::BestEffort,
    };
    let (version, private_key) = sample_version("agent.example.com");
    let material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&version, Some(SecretBytes::new(private_key)))
        .unwrap();
    let staged = sink
        .stage(
            &spec,
            &version,
            CertificateMaterialRef {
                material: &material,
            },
        )
        .await
        .unwrap();

    sink.activate(&staged).await.unwrap();
    assert_eq!(
        sink.health_check(&staged).await.unwrap(),
        DeploymentHealth::Healthy
    );
    sink.rollback(&staged).await.unwrap();
    assert!(matches!(
        sink.health_check(&staged).await.unwrap(),
        DeploymentHealth::Unhealthy(_)
    ));
    assert_eq!(
        sink.cleanup(&staged).await.unwrap(),
        CleanupOutcome::Cleaned
    );
}

fn sample_version(domain: &str) -> (CertificateVersion, String) {
    let certified = rcgen::generate_simple_self_signed([domain.to_string()]).unwrap();
    let identifiers = IdentifierSet::parse([domain]).unwrap();
    let version = CertificateVersion {
        id: VersionId::generate(),
        lineage_id: LineageId::generate(),
        identifiers,
        certificate_chain_pem: certified.cert.pem(),
        serial: "01".into(),
        not_before: "2026-01-01T00:00:00Z".into(),
        not_after: "2026-04-01T00:00:00Z".into(),
        issued_by: "contract-ca".into(),
        profile: None,
        key_ref: KeyRef::software(KeyId::generate(), KeyAlgorithm::EcP256),
        replaces: None,
        superseded_by: None,
        state: VersionState::Issued,
    };
    (version, certified.signing_key.serialize_pem())
}

fn temp_dir(name: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "acmex-t10-sink-{name}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
