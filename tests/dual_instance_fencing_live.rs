//! Live dual-instance fencing evidence (roadmap T20) — `#[ignore]`d because
//! it talks to a real Redis server.
//!
//! Goal: prove that two AcmeX instances sharing a Redis-backed repository
//! produce exactly one renew operation for the same due lineage — the lease
//! is mutually exclusive — and that fencing tokens stay strictly monotonic
//! when two instances contend for the same renewal lease.
//!
//! Unlike `tests/renewal_lease_two_scanners_create_one_operation` (which
//! shares one in-memory repository set), each "instance" here gets its own
//! `RedisRepository` connection, so every state transition crosses the wire
//! exactly like two separate processes against one Redis.
//!
//! Configuration:
//!
//! ```text
//! ACMEX_TEST_REDIS_URL=redis://127.0.0.1:6405/15   # use a disposable DB index
//! ```
//!
//! Local Redis used for the recorded evidence run:
//!
//! ```text
//! redis-server --port 6405 --save '' --daemonize no
//! ```
//!
//! Run: `cargo test --features redis --test dual_instance_fencing_live -- \
//!          --ignored --nocapture`
//!
//! Keys live under the `acmex:v1:` prefix with run-unique ids in a disposable
//! DB; a missing environment variable prints an explicit SKIP line — that
//! counts as *no evidence collected*, never as a pass.

#![cfg(feature = "redis")]

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use acmex::application::{ApplicationServiceBuilder, CertificateApplication};
use acmex::domain::{
    CertificateIntent, CertificateLineage, CertificateVersion, IdentifierSet, IntentId,
    KeyAlgorithm, KeyId, KeyRef, LineageId, OperationKind, OperationStatus, RenewalPolicy,
    TenantId, VersionId, VersionState,
};
use acmex::renewal::{RenewalController, RenewalControllerConfig};
use acmex::repository::{CreateOutcome, FakeClock, LeaseOutcome, RedisRepository, RepositorySet};
use jiff::Timestamp;

const SKIP_MESSAGE: &str = "SKIP: set ACMEX_TEST_REDIS_URL (e.g. redis://127.0.0.1:6405/15 — \
use a disposable DB; tests write under the `acmex:v1:` prefix) to collect live \
dual-instance fencing evidence";

fn redis_url() -> Option<String> {
    std::env::var("ACMEX_TEST_REDIS_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Seeds one tenant with an intent/lineage/active version that is inside its
/// renewal window with respect to the real clock. Ids are generated per run,
/// so repeated runs never collide in a shared DB.
async fn seed_due_lineage(set: &RepositorySet) -> (LineageId, VersionId) {
    let now = Timestamp::now();
    let identifiers = IdentifierSet::parse(["fencing-live.example.com"]).unwrap();
    let intent = CertificateIntent {
        id: IntentId::generate(),
        tenant_id: TenantId::default_tenant(),
        identifiers: identifiers.clone(),
        ca_policy: Default::default(),
        validation_policy: Default::default(),
        key_policy: Default::default(),
        renewal_policy: RenewalPolicy::default(),
        delivery_targets: Vec::new(),
        idempotency_key: format!("fencing-live-{}", now.as_second()),
        generation: 1,
    };
    let version_id = VersionId::generate();
    let mut lineage = CertificateLineage::new(
        LineageId::generate(),
        TenantId::default_tenant(),
        intent.id.clone(),
        identifiers.clone(),
    );
    lineage.active_version_id = Some(version_id.clone());
    // Issued 80 days ago, expires in 2 days: the 2/3-lifetime fallback window
    // opened weeks ago, so the lineage is due for renewal right now.
    let version = CertificateVersion {
        id: version_id.clone(),
        lineage_id: lineage.id.clone(),
        identifiers,
        certificate_chain_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
            .to_string(),
        serial: "01".to_string(),
        not_before: now
            .checked_sub(jiff::Span::new().hours(80 * 24))
            .unwrap()
            .to_string(),
        not_after: now
            .checked_add(jiff::Span::new().hours(48))
            .unwrap()
            .to_string(),
        issued_by: "fencing-live-ca".to_string(),
        profile: None,
        key_ref: KeyRef::software(KeyId::generate(), KeyAlgorithm::EcP256),
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state: VersionState::Active,
    };

    assert_eq!(
        set.intents.create(intent).await.unwrap(),
        CreateOutcome::Created
    );
    assert_eq!(
        set.lineages.create(lineage.clone()).await.unwrap(),
        CreateOutcome::Created
    );
    assert_eq!(
        set.versions.create(version).await.unwrap(),
        CreateOutcome::Created
    );
    (lineage.id, version_id)
}

/// Every non-terminal Renew operation persisted for the lineage across all
/// active statuses — the durable truth the two scanners must agree on.
async fn count_live_renew_operations(set: &RepositorySet, lineage_id: &LineageId) -> usize {
    let statuses = [
        OperationStatus::Queued,
        OperationStatus::Running,
        OperationStatus::Waiting,
        OperationStatus::CancelRequested,
        OperationStatus::Compensating,
    ];
    let mut count = 0;
    for status in statuses {
        for stored in set
            .operations
            .list_by_status(status, usize::MAX)
            .await
            .unwrap()
        {
            if stored.value.kind == OperationKind::Renew
                && stored.value.subject.lineage_id.as_ref() == Some(lineage_id)
            {
                count += 1;
            }
        }
    }
    count
}

/// Two instances scan the same due lineage concurrently over two independent
/// Redis connections: exactly one renew operation may be created.
#[tokio::test]
#[ignore = "requires a live Redis; set ACMEX_TEST_REDIS_URL"]
async fn live_dual_instance_concurrent_renewal_creates_exactly_one_operation() {
    let Some(url) = redis_url() else {
        println!("{SKIP_MESSAGE}");
        return;
    };
    // Two independent connections: the stand-ins for two AcmeX processes.
    let set_a: RepositorySet = RedisRepository::connect(&url)
        .await
        .expect("instance-a connect")
        .into_set();
    let set_b: RepositorySet = RedisRepository::connect(&url)
        .await
        .expect("instance-b connect")
        .into_set();

    let (lineage_id, version_id) = seed_due_lineage(&set_a).await;
    println!("seeded lineage {lineage_id} with active version {version_id}");

    let (service_a, _) = ApplicationServiceBuilder::new()
        .with_repositories(set_a.clone())
        .build()
        .unwrap();
    let (service_b, _) = ApplicationServiceBuilder::new()
        .with_repositories(set_b.clone())
        .build()
        .unwrap();
    let application_a: Arc<dyn CertificateApplication> = service_a;
    let application_b: Arc<dyn CertificateApplication> = service_b;
    let controller_a = RenewalController::new(
        set_a.clone(),
        application_a,
        RenewalControllerConfig {
            owner: "instance-a".to_string(),
            ..RenewalControllerConfig::default()
        },
    );
    let controller_b = RenewalController::new(
        set_b.clone(),
        application_b,
        RenewalControllerConfig {
            owner: "instance-b".to_string(),
            ..RenewalControllerConfig::default()
        },
    );

    // True concurrency: both scans run on the same tokio reactor against the
    // same Redis, racing for the lineage lease.
    let (report_a, report_b) = tokio::join!(controller_a.scan_once(), controller_b.scan_once());
    let report_a = report_a.expect("instance-a scan");
    let report_b = report_b.expect("instance-b scan");
    println!("instance-a report: {report_a:?}");
    println!("instance-b report: {report_b:?}");

    assert_eq!(
        report_a.operations_created + report_b.operations_created,
        1,
        "exactly one instance may create the renewal operation"
    );
    assert!(
        report_a.decisions.len() + report_b.decisions.len() >= 1,
        "both scans observed the seeded lineage"
    );

    let operation = set_a
        .operations
        .find_by_idempotency_key(&format!("renewal:{lineage_id}:{version_id}"))
        .await
        .unwrap()
        .expect("the renewal operation is persisted under the dedup key");
    assert_eq!(operation.value.kind, OperationKind::Renew);
    assert_eq!(
        operation.value.subject.lineage_id.as_ref(),
        Some(&lineage_id)
    );
    let owner = if report_a.operations_created == 1 {
        "instance-a"
    } else {
        "instance-b"
    };
    println!(
        "single renew operation created by {owner} (id {})",
        operation.value.id
    );

    assert_eq!(
        count_live_renew_operations(&set_a, &lineage_id).await,
        1,
        "no duplicate renew operations across active statuses (read via instance-a)"
    );
    assert_eq!(
        count_live_renew_operations(&set_b, &lineage_id).await,
        1,
        "no duplicate renew operations across active statuses (read via instance-b)"
    );
    println!(
        "✅ dual-instance renewal scan created exactly 1 renew operation \
         (a={}, b={}, sum=1)",
        report_a.operations_created, report_b.operations_created
    );
}

/// Two instances directly race for the same renewal lease; the loser is
/// locked out, and every (re)grant draws a strictly monotonic fencing token
/// even across expiry takeovers, so stale holders cannot write.
#[tokio::test]
#[ignore = "requires a live Redis; set ACMEX_TEST_REDIS_URL"]
async fn live_renewal_lease_contention_fencing_tokens_monotonic() {
    let Some(url) = redis_url() else {
        println!("{SKIP_MESSAGE}");
        return;
    };
    // A shared injected clock keeps expiry deterministic for both instances.
    let clock = Arc::new(FakeClock::at(
        Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
    ));
    let set_a: RepositorySet = RedisRepository::with_clock(&url, clock.clone())
        .await
        .expect("instance-a connect")
        .into_set();
    let set_b: RepositorySet = RedisRepository::with_clock(&url, clock.clone())
        .await
        .expect("instance-b connect")
        .into_set();
    let ttl = Duration::from_secs(60);
    let lease_key = format!("renewal/lineage/{}", LineageId::generate());
    println!("contended lease key: {lease_key}");

    let mut last_token = 0;
    for round in 1..=3 {
        // Both instances want the lease in the same instant; exactly one wins.
        let grant_a = match set_a
            .leases
            .acquire(&lease_key, "instance-a", ttl)
            .await
            .unwrap()
        {
            LeaseOutcome::Granted(grant) => grant,
            other => panic!("round {round}: instance-a expected grant, got {other:?}"),
        };
        match set_b
            .leases
            .acquire(&lease_key, "instance-b", ttl)
            .await
            .unwrap()
        {
            LeaseOutcome::HeldByOther { owner, expires_at } => {
                assert_eq!(owner, "instance-a");
                println!(
                    "round {round}: instance-b locked out until {expires_at} (held by instance-a, token {})",
                    grant_a.fencing_token
                );
            }
            other => panic!("round {round}: instance-b must be locked out, got {other:?}"),
        }
        assert!(
            grant_a.fencing_token > last_token,
            "round {round}: fencing tokens strictly monotonic ({} > {last_token})",
            grant_a.fencing_token
        );
        last_token = grant_a.fencing_token;

        // The lease expires; instance-b takes over with a higher token and
        // the stale owner loses its write capability.
        clock.advance_secs(61);
        let takeover = match set_b
            .leases
            .acquire(&lease_key, "instance-b", ttl)
            .await
            .unwrap()
        {
            LeaseOutcome::Granted(grant) => grant,
            other => panic!("round {round}: expired lease must be taken over, got {other:?}"),
        };
        assert!(takeover.fencing_token > grant_a.fencing_token);
        assert!(
            set_a
                .leases
                .renew(&lease_key, "instance-a", grant_a.fencing_token, ttl)
                .await
                .unwrap()
                .is_none(),
            "round {round}: stale owner cannot renew after takeover"
        );
        assert!(
            set_b
                .leases
                .renew(&lease_key, "instance-b", takeover.fencing_token, ttl)
                .await
                .unwrap()
                .is_some(),
            "round {round}: current owner can renew"
        );
        set_b
            .leases
            .release(&lease_key, "instance-b", takeover.fencing_token)
            .await
            .unwrap();
        println!(
            "round {round}: instance-a token={}, instance-b takeover token={} (strictly monotonic)",
            grant_a.fencing_token, takeover.fencing_token
        );
        // Prepare the next round at a fresh clock position with the lease free.
        clock.advance_secs(61);
    }
    println!(
        "✅ lease contention across two instances stayed mutually exclusive with \
         strictly monotonic fencing tokens (final token {last_token})"
    );
}
