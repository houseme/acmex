use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use acmex::domain::{
    CaPolicy, DeliveryTarget, DeploymentId, IntentId, OperationStatus, RenewalPolicy, TenantId,
    ValidationPolicy,
};
use acmex::error::{AcmeError, Result};
use acmex::repository::{MemoryRepository, RepositorySet};
use acmex::{
    CertificateIntent, CertificateLineage, CertificateMaterialBuilder, CertificateMaterialRef,
    CertificateSink, CertificateVersion, CleanupOutcome, DeliveryRequirement, DeliveryTargetKind,
    DeploymentActivationOutcome, DeploymentHealth, DeploymentOrchestrator, DeploymentSpec,
    FakeAgentCertificateSink, FileCertificateSink, IdentifierSet, KeyAlgorithm, KeyId, KeyPolicy,
    KeyRef, LineageId, SecretBytes, TargetId, VersionId, VersionState,
};
use async_trait::async_trait;

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

#[tokio::test]
async fn deployment_orchestrator_activates_only_after_required_and_quorum_are_healthy() {
    let set = MemoryRepository::new().into_set();
    let lineage_id = LineageId::generate();
    let (old_version, old_key) = sample_version_for_lineage("old.example.com", lineage_id.clone());
    let (new_version, new_key) = sample_version_for_lineage("new.example.com", lineage_id.clone());
    seed_lineage_with_versions(
        &set,
        lineage_id.clone(),
        old_version.clone(),
        new_version.clone(),
    )
    .await;
    seed_intent(
        &set,
        &lineage_id,
        new_version.identifiers.clone(),
        vec![
            target(
                "required",
                DeliveryTargetKind::File,
                temp_dir("required").display().to_string(),
                DeliveryRequirement::Required,
            ),
            target(
                "quorum-a",
                DeliveryTargetKind::Webhook,
                "agent-a".into(),
                DeliveryRequirement::Quorum(1),
            ),
            target(
                "quorum-b",
                DeliveryTargetKind::Webhook,
                "agent-b".into(),
                DeliveryRequirement::Quorum(1),
            ),
            target(
                "best-effort",
                DeliveryTargetKind::Webhook,
                "agent-best-effort".into(),
                DeliveryRequirement::BestEffort,
            ),
        ],
    )
    .await;
    let orchestrator = DeploymentOrchestrator::new(set.clone())
        .register_sink(
            DeliveryTargetKind::File,
            Arc::new(FileCertificateSink::new()),
        )
        .register_sink(
            DeliveryTargetKind::Webhook,
            Arc::new(FakeAgentCertificateSink::new()),
        );
    let old_material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&old_version, Some(SecretBytes::new(old_key)))
        .unwrap();
    let new_material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&new_version, Some(SecretBytes::new(new_key)))
        .unwrap();

    let deployments = orchestrator
        .schedule_deployments_for_version(&new_version.id, &[])
        .await
        .unwrap();
    let waiting = orchestrator
        .activate_version_when_deployments_satisfied(&new_version.id)
        .await
        .unwrap();
    assert!(matches!(
        waiting,
        DeploymentActivationOutcome::Waiting { .. }
    ));

    run_to_healthy(
        &orchestrator,
        deployment_id(&new_version.id, "required"),
        &new_material,
    )
    .await;
    run_to_healthy(
        &orchestrator,
        deployment_id(&new_version.id, "quorum-a"),
        &new_material,
    )
    .await;
    let rescheduled = orchestrator
        .schedule_deployments_for_version(&new_version.id, &[])
        .await
        .unwrap();
    let required_target_id = TargetId::new("required").unwrap();
    let required_after_reschedule = rescheduled
        .iter()
        .find(|deployment| deployment.target_id == required_target_id)
        .unwrap();
    let scheduled_events = set
        .outbox
        .list_pending(100)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.event_type == "deployment.scheduled")
        .count();
    let activated = orchestrator
        .activate_version_when_deployments_satisfied(&new_version.id)
        .await
        .unwrap();
    let lineage = set.lineages.get(&lineage_id).await.unwrap().unwrap().value;
    let old_after = set
        .versions
        .get(&old_version.id)
        .await
        .unwrap()
        .unwrap()
        .value;

    assert_eq!(deployments.len(), 4);
    assert_eq!(rescheduled.len(), 4);
    assert_eq!(
        required_after_reschedule.state,
        acmex::domain::DeploymentState::Healthy
    );
    assert_eq!(scheduled_events, 4);
    assert!(matches!(
        activated,
        DeploymentActivationOutcome::Activated { .. }
    ));
    assert_eq!(lineage.active_version_id, Some(new_version.id));
    assert_eq!(old_after.state, VersionState::Superseded);
    assert_eq!(old_material.leaf_sha256.len(), 64);
}

#[tokio::test]
async fn deployment_failure_keeps_new_version_and_old_active_pointer_intact() {
    let set = MemoryRepository::new().into_set();
    let lineage_id = LineageId::generate();
    let (old_version, old_key) =
        sample_version_for_lineage("old-fail.example.com", lineage_id.clone());
    let (new_version, new_key) =
        sample_version_for_lineage("new-fail.example.com", lineage_id.clone());
    seed_lineage_with_versions(
        &set,
        lineage_id.clone(),
        old_version.clone(),
        new_version.clone(),
    )
    .await;
    seed_intent(
        &set,
        &lineage_id,
        new_version.identifiers.clone(),
        vec![target(
            "required-failing",
            DeliveryTargetKind::Webhook,
            "agent-failing".into(),
            DeliveryRequirement::Required,
        )],
    )
    .await;
    let orchestrator = DeploymentOrchestrator::new(set.clone())
        .register_sink(DeliveryTargetKind::Webhook, Arc::new(FailingSink));
    let material = CertificateMaterialBuilder::new()
        .require_private_key()
        .build(&new_version, Some(SecretBytes::new(new_key)))
        .unwrap();

    orchestrator
        .schedule_deployments_for_version(&new_version.id, &[])
        .await
        .unwrap();
    let failed = orchestrator
        .run_deployment_once(
            &deployment_id(&new_version.id, "required-failing"),
            &material,
        )
        .await
        .unwrap();
    let activation = orchestrator
        .activate_version_when_deployments_satisfied(&new_version.id)
        .await
        .unwrap();
    let lineage = set.lineages.get(&lineage_id).await.unwrap().unwrap().value;
    let new_after = set
        .versions
        .get(&new_version.id)
        .await
        .unwrap()
        .unwrap()
        .value;
    let operation = set
        .operations
        .get(&operation_id(&new_version.id, "required-failing"))
        .await
        .unwrap()
        .unwrap()
        .value;
    let events = set.outbox.list_pending(100).await.unwrap();

    assert_eq!(failed.state, acmex::domain::DeploymentState::Failed);
    assert!(matches!(
        activation,
        DeploymentActivationOutcome::Waiting { .. }
    ));
    assert_eq!(lineage.active_version_id, Some(old_version.id));
    assert_eq!(new_after.state, VersionState::Issued);
    assert_eq!(operation.status, OperationStatus::Failed);
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "deployment.failed")
    );
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "deployment.scheduled")
    );
    assert!(old_key.contains("BEGIN PRIVATE KEY"));
}

fn sample_version(domain: &str) -> (CertificateVersion, String) {
    sample_version_for_lineage(domain, LineageId::generate())
}

fn sample_version_for_lineage(domain: &str, lineage_id: LineageId) -> (CertificateVersion, String) {
    let certified = rcgen::generate_simple_self_signed([domain.to_string()]).unwrap();
    let identifiers = IdentifierSet::parse([domain]).unwrap();
    let version = CertificateVersion {
        id: VersionId::generate(),
        lineage_id,
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

async fn seed_lineage_with_versions(
    set: &RepositorySet,
    lineage_id: LineageId,
    mut old_version: CertificateVersion,
    new_version: CertificateVersion,
) {
    old_version.state = VersionState::Active;
    let intent_id = IntentId::generate();
    let mut lineage = CertificateLineage::new(
        lineage_id,
        TenantId::default_tenant(),
        intent_id,
        new_version.identifiers.clone(),
    );
    lineage.active_version_id = Some(old_version.id.clone());
    set.lineages.create(lineage).await.unwrap();
    set.versions.create(old_version).await.unwrap();
    set.versions.create(new_version).await.unwrap();
}

async fn seed_intent(
    set: &RepositorySet,
    lineage_id: &LineageId,
    identifiers: IdentifierSet,
    delivery_targets: Vec<DeliveryTarget>,
) {
    let lineage = set.lineages.get(lineage_id).await.unwrap().unwrap();
    let intent = CertificateIntent {
        id: lineage.value.intent_id.clone(),
        tenant_id: TenantId::default_tenant(),
        identifiers,
        ca_policy: CaPolicy::default(),
        validation_policy: ValidationPolicy::default(),
        key_policy: KeyPolicy::default(),
        renewal_policy: RenewalPolicy::default(),
        delivery_targets,
        idempotency_key: "deployment-orchestrator-test".into(),
        generation: 1,
    };
    set.intents.create(intent).await.unwrap();
}

fn target(
    id: &str,
    kind: DeliveryTargetKind,
    reference: String,
    requirement: DeliveryRequirement,
) -> DeliveryTarget {
    DeliveryTarget {
        id: TargetId::new(id).unwrap(),
        kind,
        reference,
        requirement,
    }
}

async fn run_to_healthy(
    orchestrator: &DeploymentOrchestrator,
    deployment_id: DeploymentId,
    material: &acmex::CertificateMaterial,
) {
    let staged = orchestrator
        .run_deployment_once(&deployment_id, material)
        .await
        .unwrap();
    assert_eq!(staged.state, acmex::domain::DeploymentState::Staged);
    let active = orchestrator
        .run_deployment_once(&deployment_id, material)
        .await
        .unwrap();
    assert_eq!(active.state, acmex::domain::DeploymentState::Active);
    let healthy = orchestrator
        .run_deployment_once(&deployment_id, material)
        .await
        .unwrap();
    assert_eq!(healthy.state, acmex::domain::DeploymentState::Healthy);
}

fn deployment_id(version_id: &VersionId, target: &str) -> DeploymentId {
    DeploymentId::new(format!(
        "dep_{}_{}",
        version_id.as_str(),
        TargetId::new(target).unwrap().as_str()
    ))
    .unwrap()
}

fn operation_id(version_id: &VersionId, target: &str) -> acmex::domain::OperationId {
    acmex::domain::OperationId::new(format!(
        "op_deploy_{}_{}",
        version_id.as_str(),
        TargetId::new(target).unwrap().as_str()
    ))
    .unwrap()
}

#[derive(Debug)]
struct FailingSink;

#[async_trait]
impl CertificateSink for FailingSink {
    async fn stage(
        &self,
        _spec: &DeploymentSpec,
        _version: &CertificateVersion,
        _material: CertificateMaterialRef<'_>,
    ) -> Result<acmex::StagedDeployment> {
        Err(AcmeError::transport("agent offline"))
    }

    async fn activate(&self, _staged: &acmex::StagedDeployment) -> Result<()> {
        Ok(())
    }

    async fn health_check(&self, _staged: &acmex::StagedDeployment) -> Result<DeploymentHealth> {
        Ok(DeploymentHealth::Unknown("not staged".into()))
    }

    async fn rollback(&self, _staged: &acmex::StagedDeployment) -> Result<()> {
        Ok(())
    }

    async fn cleanup(&self, _staged: &acmex::StagedDeployment) -> Result<CleanupOutcome> {
        Ok(CleanupOutcome::AlreadyClean)
    }
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
