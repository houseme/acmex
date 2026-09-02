use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;

use acmex::application::{
    ApplicationServiceBuilder, CancelOperation, CertificateApplication, CreateCertificateIntent,
    DeployCertificate, IntentView, IssueCertificate, OperationView, RenewCertificate,
    RevokeCertificate,
};
use acmex::ca_backend::RenewalWindow;
use acmex::domain::{
    CertificateIntent, CertificateLineage, CertificateVersion, DeliveryTarget, DeliveryTargetKind,
    DeploymentId, DeploymentRecord, DeploymentState, IdentifierSet, IntentId, KeyAlgorithm, KeyId,
    KeyRef, LineageId, OperationId, OperationKind, OperationRecord, OperationRef, OperationSubject,
    RenewalPolicy, TargetId, TenantId, VersionId, VersionState,
};
use acmex::error::{AcmeError, Result};
use acmex::renewal::{
    RenewalActivationOutcome, RenewalController, RenewalControllerConfig, RenewalInfoProvider,
    RenewalPriority, RenewalWindowSource, calculate_decision,
};
use acmex::repository::{CreateOutcome, FakeClock, LeaseOutcome, MemoryRepository, RepositorySet};

fn ts(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn sample_intent(
    id: IntentId,
    identifiers: IdentifierSet,
    policy: RenewalPolicy,
) -> CertificateIntent {
    CertificateIntent {
        id,
        tenant_id: TenantId::default_tenant(),
        identifiers,
        ca_policy: Default::default(),
        validation_policy: Default::default(),
        key_policy: Default::default(),
        renewal_policy: policy,
        delivery_targets: Vec::new(),
        idempotency_key: "intent-key".to_string(),
        generation: 1,
    }
}

fn sample_lineage(
    id: LineageId,
    intent_id: IntentId,
    identifiers: IdentifierSet,
    active_version_id: VersionId,
) -> CertificateLineage {
    let mut lineage =
        CertificateLineage::new(id, TenantId::default_tenant(), intent_id, identifiers);
    lineage.active_version_id = Some(active_version_id);
    lineage
}

fn sample_version(
    id: VersionId,
    lineage_id: LineageId,
    identifiers: IdentifierSet,
    not_before: &str,
    not_after: &str,
) -> CertificateVersion {
    CertificateVersion {
        id,
        lineage_id,
        identifiers,
        certificate_chain_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
            .to_string(),
        serial: "01".to_string(),
        not_before: not_before.to_string(),
        not_after: not_after.to_string(),
        issued_by: "test-ca".to_string(),
        profile: None,
        key_ref: KeyRef::software(KeyId::generate(), KeyAlgorithm::EcP256),
        replaces: None,
        superseded_by: None,
        state: VersionState::Active,
    }
}

#[tokio::test]
async fn renewal_short_lived_fallback_uses_lifetime_fraction_not_fixed_days() {
    let identifiers = IdentifierSet::parse(["192.0.2.10"]).unwrap();
    let intent = sample_intent(
        IntentId::new("int_short").unwrap(),
        identifiers.clone(),
        RenewalPolicy::default(),
    );
    let lineage = sample_lineage(
        LineageId::new("lin_short").unwrap(),
        intent.id.clone(),
        identifiers.clone(),
        VersionId::new("ver_short").unwrap(),
    );
    let version = sample_version(
        VersionId::new("ver_short").unwrap(),
        lineage.id.clone(),
        identifiers,
        "2026-01-01T00:00:00Z",
        "2026-01-07T16:00:00Z",
    );

    let decision = calculate_decision(
        &lineage,
        &version,
        &intent,
        None,
        ts("2026-01-05T11:00:00Z"),
    )
    .unwrap();

    assert_eq!(decision.source, RenewalWindowSource::LifetimeFraction);
    assert_eq!(decision.window_start, ts("2026-01-05T10:40:00Z"));
    assert!(decision.selected_at >= decision.window_start);
    assert!(decision.selected_at <= decision.safety_deadline);
}

#[tokio::test]
async fn renewal_ari_window_overrides_fallback() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let policy = RenewalPolicy {
        fixed_renew_before: Some(Duration::from_secs(30 * 24 * 3600)),
        ..RenewalPolicy::default()
    };
    let intent = sample_intent(
        IntentId::new("int_ari").unwrap(),
        identifiers.clone(),
        policy,
    );
    let lineage = sample_lineage(
        LineageId::new("lin_ari").unwrap(),
        intent.id.clone(),
        identifiers.clone(),
        VersionId::new("ver_ari").unwrap(),
    );
    let version = sample_version(
        VersionId::new("ver_ari").unwrap(),
        lineage.id.clone(),
        identifiers,
        "2026-01-01T00:00:00Z",
        "2026-04-01T00:00:00Z",
    );
    let ari = RenewalWindow {
        start: ts("2026-03-20T00:00:00Z"),
        end: ts("2026-03-22T00:00:00Z"),
        retry_after: None,
        explanation_url: None,
    };

    let decision = calculate_decision(
        &lineage,
        &version,
        &intent,
        Some(ari),
        ts("2026-03-20T01:00:00Z"),
    )
    .unwrap();

    assert_eq!(decision.source, RenewalWindowSource::Ari);
    assert_eq!(decision.window_start, ts("2026-03-20T00:00:00Z"));
    assert_eq!(decision.window_end, ts("2026-03-22T00:00:00Z"));
}

#[tokio::test]
async fn renewal_jitter_is_stable_and_distributes_lineages() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let intent = sample_intent(
        IntentId::new("int_jitter").unwrap(),
        identifiers.clone(),
        RenewalPolicy::default(),
    );
    let lineage_a = sample_lineage(
        LineageId::new("lin_jitter_a").unwrap(),
        intent.id.clone(),
        identifiers.clone(),
        VersionId::new("ver_jitter").unwrap(),
    );
    let lineage_b = sample_lineage(
        LineageId::new("lin_jitter_b").unwrap(),
        intent.id.clone(),
        identifiers.clone(),
        VersionId::new("ver_jitter").unwrap(),
    );
    let version = sample_version(
        VersionId::new("ver_jitter").unwrap(),
        lineage_a.id.clone(),
        identifiers,
        "2026-01-01T00:00:00Z",
        "2026-04-01T00:00:00Z",
    );

    let first = calculate_decision(
        &lineage_a,
        &version,
        &intent,
        None,
        ts("2026-02-01T00:00:00Z"),
    )
    .unwrap();
    let second = calculate_decision(
        &lineage_a,
        &version,
        &intent,
        None,
        ts("2026-02-02T00:00:00Z"),
    )
    .unwrap();
    let different = calculate_decision(
        &lineage_b,
        &version,
        &intent,
        None,
        ts("2026-02-01T00:00:00Z"),
    )
    .unwrap();

    assert_eq!(first.selected_at, second.selected_at);
    assert_ne!(first.selected_at, different.selected_at);
}

#[derive(Debug)]
struct StaticAri(Option<RenewalWindow>);

#[async_trait]
impl RenewalInfoProvider for StaticAri {
    async fn renewal_window(&self, _chain_pem: &str) -> Result<Option<RenewalWindow>> {
        Ok(self.0.clone())
    }
}

struct FailingRenewApplication;

#[async_trait]
impl CertificateApplication for FailingRenewApplication {
    async fn create_intent(&self, _command: CreateCertificateIntent) -> Result<IntentView> {
        Err(AcmeError::transport("forced create failure"))
    }

    async fn issue(&self, _command: IssueCertificate) -> Result<OperationRef> {
        Err(AcmeError::transport("forced issue failure"))
    }

    async fn renew(&self, _command: RenewCertificate) -> Result<OperationRef> {
        Err(AcmeError::transport("forced renewal failure"))
    }

    async fn revoke(&self, _command: RevokeCertificate) -> Result<OperationRef> {
        Err(AcmeError::transport("forced revoke failure"))
    }

    async fn deploy(&self, _command: DeployCertificate) -> Result<OperationRef> {
        Err(AcmeError::transport("forced deploy failure"))
    }

    async fn cancel_operation(&self, _command: CancelOperation) -> Result<OperationView> {
        Err(AcmeError::transport("forced cancel failure"))
    }
}

async fn seeded_controller(
    now: Timestamp,
) -> (
    RepositorySet,
    Arc<dyn CertificateApplication>,
    LineageId,
    VersionId,
) {
    let clock = Arc::new(FakeClock::at(now));
    let repositories = MemoryRepository::with_clock(clock).into_set();
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let intent_id = IntentId::new("int_scan").unwrap();
    let lineage_id = LineageId::new("lin_scan").unwrap();
    let version_id = VersionId::new("ver_scan").unwrap();
    let policy = RenewalPolicy {
        min_safety_margin: Duration::from_secs(24 * 3600),
        ..RenewalPolicy::default()
    };
    let intent = sample_intent(intent_id.clone(), identifiers.clone(), policy);
    let lineage = sample_lineage(
        lineage_id.clone(),
        intent_id,
        identifiers.clone(),
        version_id.clone(),
    );
    let version = sample_version(
        version_id.clone(),
        lineage_id.clone(),
        identifiers,
        "2026-01-01T00:00:00Z",
        "2026-01-10T00:00:00Z",
    );

    assert_eq!(
        repositories.intents.create(intent).await.unwrap(),
        CreateOutcome::Created
    );
    assert_eq!(
        repositories.lineages.create(lineage).await.unwrap(),
        CreateOutcome::Created
    );
    assert_eq!(
        repositories.versions.create(version).await.unwrap(),
        CreateOutcome::Created
    );
    let (service, _) = ApplicationServiceBuilder::new()
        .with_repositories(repositories.clone())
        .build()
        .unwrap();
    (repositories, service, lineage_id, version_id)
}

async fn seeded_activation(
    healthy_deployment: bool,
) -> (
    RepositorySet,
    RenewalController,
    LineageId,
    VersionId,
    VersionId,
    TargetId,
) {
    let clock = Arc::new(FakeClock::at(ts("2026-01-09T12:00:00Z")));
    let repositories = MemoryRepository::with_clock(clock).into_set();
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let intent_id = IntentId::new("int_activate").unwrap();
    let lineage_id = LineageId::new("lin_activate").unwrap();
    let old_version_id = VersionId::new("ver_old").unwrap();
    let new_version_id = VersionId::new("ver_new").unwrap();
    let target = DeliveryTarget::new("web", DeliveryTargetKind::File, "/tmp/acmex").unwrap();
    let target_id = target.id.clone();
    let mut intent = sample_intent(
        intent_id.clone(),
        identifiers.clone(),
        RenewalPolicy::default(),
    );
    intent.delivery_targets = vec![target];
    let lineage = sample_lineage(
        lineage_id.clone(),
        intent_id,
        identifiers.clone(),
        old_version_id.clone(),
    );
    let old_version = sample_version(
        old_version_id.clone(),
        lineage_id.clone(),
        identifiers.clone(),
        "2026-01-01T00:00:00Z",
        "2026-01-10T00:00:00Z",
    );
    let mut new_version = sample_version(
        new_version_id.clone(),
        lineage_id.clone(),
        identifiers,
        "2026-01-07T00:00:00Z",
        "2026-01-17T00:00:00Z",
    );
    new_version.state = VersionState::Issued;
    new_version.replaces = Some(old_version_id.clone());
    let mut deployment = DeploymentRecord::new(
        DeploymentId::new("dep_web").unwrap(),
        new_version_id.clone(),
        lineage_id.clone(),
        target_id.clone(),
        ts("2026-01-09T12:00:00Z"),
    );
    if healthy_deployment {
        deployment.state = DeploymentState::Healthy;
    }

    repositories.intents.create(intent).await.unwrap();
    repositories.lineages.create(lineage).await.unwrap();
    repositories.versions.create(old_version).await.unwrap();
    repositories.versions.create(new_version).await.unwrap();
    repositories.deployments.create(deployment).await.unwrap();

    let (service, _) = ApplicationServiceBuilder::new()
        .with_repositories(repositories.clone())
        .build()
        .unwrap();
    let application: Arc<dyn CertificateApplication> = service;
    let controller = RenewalController::new(
        repositories.clone(),
        application,
        RenewalControllerConfig::default(),
    );
    (
        repositories,
        controller,
        lineage_id,
        old_version_id,
        new_version_id,
        target_id,
    )
}

#[tokio::test]
async fn renewal_lease_two_scanners_create_one_operation() {
    let (repositories, application, lineage_id, version_id) =
        seeded_controller(ts("2026-01-09T12:00:00Z")).await;
    let config = RenewalControllerConfig {
        owner: "scanner-a".to_string(),
        ..RenewalControllerConfig::default()
    };
    let controller_a = RenewalController::new(repositories.clone(), application.clone(), config);
    let controller_b = RenewalController::new(
        repositories.clone(),
        application,
        RenewalControllerConfig {
            owner: "scanner-b".to_string(),
            ..RenewalControllerConfig::default()
        },
    );

    let first = controller_a.scan_once().await.unwrap();
    let second = controller_b.scan_once().await.unwrap();
    let created = repositories
        .operations
        .find_by_idempotency_key(&format!("renewal:{lineage_id}:{version_id}"))
        .await
        .unwrap();

    assert_eq!(first.operations_created + second.operations_created, 1);
    let operation = created.unwrap().value;
    assert_eq!(operation.kind, OperationKind::Renew);
    assert_eq!(operation.subject.lineage_id.as_ref(), Some(&lineage_id));
}

#[tokio::test]
async fn renewal_scan_shadow_mode_does_not_create_operation() {
    let (repositories, application, lineage_id, version_id) =
        seeded_controller(ts("2026-01-09T12:00:00Z")).await;
    let controller = RenewalController::new(
        repositories.clone(),
        application,
        RenewalControllerConfig {
            shadow_mode: true,
            ..RenewalControllerConfig::default()
        },
    )
    .with_ari_provider(Arc::new(StaticAri(None)));

    let report = controller.scan_once().await.unwrap();
    let created = repositories
        .operations
        .find_by_idempotency_key(&format!("renewal:{lineage_id}:{version_id}"))
        .await
        .unwrap();

    assert_eq!(report.shadowed, 1);
    assert_eq!(report.operations_created, 0);
    assert!(created.is_none());
}

#[tokio::test]
async fn renewal_scan_skips_lineage_with_existing_active_renewal_operation() {
    let (repositories, application, lineage_id, version_id) =
        seeded_controller(ts("2026-01-09T12:00:00Z")).await;
    let operation = OperationRecord::new(
        OperationId::new("op_existing_renewal").unwrap(),
        OperationKind::Renew,
        OperationSubject {
            intent_id: None,
            lineage_id: Some(lineage_id.clone()),
            version_id: None,
        },
        Some("existing-renewal".to_string()),
        None,
        repositories.clock.now(),
    );
    repositories.operations.create(operation).await.unwrap();
    let controller = RenewalController::new(
        repositories.clone(),
        application,
        RenewalControllerConfig::default(),
    );

    let report = controller.scan_once().await.unwrap();
    let created = repositories
        .operations
        .find_by_idempotency_key(&format!("renewal:{lineage_id}:{version_id}"))
        .await
        .unwrap();

    assert_eq!(report.decisions.len(), 1);
    assert_eq!(report.operations_created, 0);
    assert_eq!(report.leases_skipped, 0);
    assert!(created.is_none());
}

#[tokio::test]
async fn renewal_scan_releases_lineage_lease_when_operation_creation_fails() {
    let (repositories, _application, lineage_id, _version_id) =
        seeded_controller(ts("2026-01-09T12:00:00Z")).await;
    let controller = RenewalController::new(
        repositories.clone(),
        Arc::new(FailingRenewApplication),
        RenewalControllerConfig {
            owner: "scanner-a".to_string(),
            ..RenewalControllerConfig::default()
        },
    );

    let result = controller.scan_once().await;
    let reacquired = repositories
        .leases
        .acquire(
            &format!("renewal/lineage/{lineage_id}"),
            "scanner-b",
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    assert!(result.is_err());
    assert!(matches!(reacquired, LeaseOutcome::Granted(_)));
}

#[tokio::test]
async fn renewal_safety_deadline_escalates_priority() {
    let identifiers = IdentifierSet::parse(["example.com"]).unwrap();
    let intent = sample_intent(
        IntentId::new("int_deadline").unwrap(),
        identifiers.clone(),
        RenewalPolicy::default(),
    );
    let lineage = sample_lineage(
        LineageId::new("lin_deadline").unwrap(),
        intent.id.clone(),
        identifiers.clone(),
        VersionId::new("ver_deadline").unwrap(),
    );
    let version = sample_version(
        VersionId::new("ver_deadline").unwrap(),
        lineage.id.clone(),
        identifiers,
        "2026-01-01T00:00:00Z",
        "2026-04-01T00:00:00Z",
    );

    let decision = calculate_decision(
        &lineage,
        &version,
        &intent,
        None,
        ts("2026-03-29T00:00:00Z"),
    )
    .unwrap();

    assert_eq!(decision.priority, RenewalPriority::Critical);
}

#[tokio::test]
async fn renewal_activation_waits_until_required_deployment_is_healthy() {
    let (repositories, controller, lineage_id, old_version_id, new_version_id, target_id) =
        seeded_activation(false).await;

    let outcome = controller
        .activate_renewed_version(&new_version_id)
        .await
        .unwrap();

    assert_eq!(
        outcome,
        RenewalActivationOutcome::WaitingForDeployments {
            lineage_id: lineage_id.clone(),
            version_id: new_version_id.clone(),
            missing_targets: vec![target_id],
        }
    );
    let lineage = repositories
        .lineages
        .get(&lineage_id)
        .await
        .unwrap()
        .unwrap()
        .value;
    assert_eq!(lineage.active_version_id.as_ref(), Some(&old_version_id));
}

#[tokio::test]
async fn renewal_activation_switches_active_version_and_supersedes_old_after_deploy() {
    let (repositories, controller, lineage_id, old_version_id, new_version_id, _target_id) =
        seeded_activation(true).await;

    let outcome = controller
        .activate_renewed_version(&new_version_id)
        .await
        .unwrap();

    assert_eq!(
        outcome,
        RenewalActivationOutcome::Activated {
            lineage_id: lineage_id.clone(),
            version_id: new_version_id.clone(),
            superseded_version_id: Some(old_version_id.clone()),
        }
    );
    let lineage = repositories
        .lineages
        .get(&lineage_id)
        .await
        .unwrap()
        .unwrap()
        .value;
    let old_version = repositories
        .versions
        .get(&old_version_id)
        .await
        .unwrap()
        .unwrap()
        .value;
    let new_version = repositories
        .versions
        .get(&new_version_id)
        .await
        .unwrap()
        .unwrap()
        .value;

    assert_eq!(lineage.active_version_id.as_ref(), Some(&new_version_id));
    assert_eq!(new_version.state, VersionState::Active);
    assert_eq!(old_version.state, VersionState::Superseded);
    assert_eq!(old_version.superseded_by.as_ref(), Some(&new_version_id));
}

#[tokio::test]
async fn renewal_scan_records_metrics() {
    let (repositories, application, _lineage_id, _version_id) =
        seeded_controller(ts("2026-01-09T12:00:00Z")).await;
    let metrics = Arc::new(acmex::metrics::MetricsRegistry::new());
    let controller = RenewalController::new(
        repositories.clone(),
        application,
        RenewalControllerConfig::default(),
    )
    .with_metrics(metrics.clone());

    let report = controller.scan_once().await.unwrap();

    let text = metrics.gather_text();
    // Active-version expiry gauge in seconds (positive: ~12h remain).
    let expiry_line = text
        .lines()
        .find(|line| {
            line.starts_with(r#"acmex_certificate_seconds_to_expiry{ca="any",state="active""#)
        })
        .unwrap_or_else(|| panic!("missing expiry gauge:\n{text}"));
    let value: i64 = expiry_line.rsplit(' ').next().unwrap().parse().unwrap();
    assert!(
        (0..=86_400).contains(&value),
        "expiry gauge should be ~12h in seconds, got {value}"
    );

    // Due renewals are counted by priority (seeded lineage is critical here).
    if report.operations_created > 0 {
        assert!(
            text.contains(r#"acmex_renewal_due{ca="any",priority="critical"} 1"#),
            "{text}"
        );
    }
}

#[tokio::test]
async fn renewal_scan_records_failure_metric() {
    let (repositories, _application, _lineage_id, _version_id) =
        seeded_controller(ts("2026-01-09T12:00:00Z")).await;
    let metrics = Arc::new(acmex::metrics::MetricsRegistry::new());
    let controller = RenewalController::new(
        repositories.clone(),
        Arc::new(FailingRenewApplication),
        RenewalControllerConfig {
            owner: "scanner-a".to_string(),
            ..RenewalControllerConfig::default()
        },
    )
    .with_metrics(metrics.clone());

    // The scan surfaces the failure after recording it.
    assert!(controller.scan_once().await.is_err());

    let text = metrics.gather_text();
    assert!(
        text.contains(r#"acmex_renewal_failures_total{ca="any",error_class="retryable"} 1"#),
        "{text}"
    );
}
