//! Renewal decisions with the v0.9+ [`acmex::renewal::RenewalController`].
//!
//! This replaces the old `advanced_scheduler.rs` demo of the deprecated
//! `AdvancedRenewalScheduler` (removed `#![allow(deprecated)]` and all).
//! Renewal today is a repository-backed controller: on every scan pass it
//! evaluates each certificate lineage's active version and derives a
//! stable, jittered renewal window from the intent's renewal policy (or an
//! RFC 9773 ARI suggestion when the CA offers one). Due lineages get a
//! durable Renew operation — unless the controller runs in `shadow_mode`,
//! which only reports what it *would* do.
//!
//! This demo stays fully offline and CA-free:
//!
//! 1. seed an in-memory repository with one intent/lineage/version;
//! 2. call the pure [`acmex::renewal::calculate_decision`] at a few
//!    instants inside the derived window (dry-run tooling does the same);
//! 3. run one `shadow_mode` scan pass and inspect the scan report;
//! 4. run a real pass and watch the durable Renew operation appear.
//!
//! Run it:
//!
//! ```text
//! cargo run --example renewal_controller
//! ```

use std::str::FromStr;
use std::sync::Arc;

use acmex::application::{
    ActorContext, ApplicationServiceBuilder, CertificateApplication, CreateCertificateIntent,
};
use acmex::domain::{
    CertificateLineage, CertificateVersion, IdentifierSet, KeyAlgorithm, KeyId, KeyRef, LineageId,
    OperationStatus, TenantId, VersionId, VersionState,
};
use acmex::renewal::{
    RenewalController, RenewalControllerConfig, RenewalDecision, calculate_decision,
};
use acmex::repository::{Clock, FakeClock, MemoryRepository};
use jiff::Timestamp;

/// Fixed wall clock used for the whole demo.
const NOW: &str = "2026-01-01T00:00:00Z";
/// The active certificate's validity: 90 days starting now.
const NOT_BEFORE: &str = "2026-01-01T00:00:00Z";
const NOT_AFTER: &str = "2026-04-01T00:00:00Z";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ---------------------------------------------------------------------------
    // 1. Seed the repository: intent (via the application service), lineage
    //    and one active version.
    // ---------------------------------------------------------------------------
    let clock = Arc::new(FakeClock::at(Timestamp::from_str(NOW)?));
    let (service, repositories) = ApplicationServiceBuilder::new()
        .with_repositories(MemoryRepository::with_clock(clock.clone()).into_set())
        .build()?;

    let intent_view = service
        .create_intent(CreateCertificateIntent {
            context: ActorContext::default(),
            identifiers: vec!["example.com".to_string()],
            ca_policy: Default::default(),
            validation_policy: Default::default(),
            key_policy: Default::default(),
            renewal_policy: Default::default(),
            delivery_targets: Vec::new(),
            idempotency_key: "renewal-controller-demo".to_string(),
        })
        .await?;
    let identifiers = IdentifierSet::parse(["example.com"])?;
    let lineage_id = LineageId::new("lin_demo")?;
    let version_id = VersionId::new("ver_current")?;
    let mut lineage = CertificateLineage::new(
        lineage_id.clone(),
        TenantId::default_tenant(),
        intent_view.id.clone(),
        identifiers.clone(),
    );
    lineage.active_version_id = Some(version_id.clone());
    repositories.lineages.create(lineage.clone()).await?;

    repositories
        .versions
        .create(active_version(
            version_id.clone(),
            lineage_id.clone(),
            identifiers,
        ))
        .await?;
    println!("seeded lineage {lineage_id} with active version {version_id}");
    println!("certificate validity: {NOT_BEFORE} .. {NOT_AFTER}\n");

    // ---------------------------------------------------------------------------
    // 2. The pure decision calculator: what dry-run tooling calls.
    // ---------------------------------------------------------------------------
    let version = repositories
        .versions
        .get(&version_id)
        .await?
        .ok_or("seeded version is missing")?
        .value;
    // The controller reads the stored intent; the view returned by the
    // service is the API projection of the same record.
    let intent = repositories
        .intents
        .get(&intent_view.id)
        .await?
        .ok_or("seeded intent is missing")?
        .value;
    let base = calculate_decision(&lineage, &version, &intent, None, clock.now())?;
    println!("derived renewal window (policy: 2/3 lifetime fraction, 3-day safety margin):");
    println!("  window_start    = {}", base.window_start);
    println!(
        "  selected_at     = {}  (stable jitter per lineage+version)",
        base.selected_at
    );
    println!("  safety_deadline = {}", base.safety_deadline);

    for (label, now) in [
        ("long before the window", base.window_start),
        ("at the selected instant", base.selected_at),
        ("past the safety deadline", base.safety_deadline),
    ] {
        let decision = calculate_decision(&lineage, &version, &intent, None, now)?;
        print_decision(label, &decision);
    }

    // ---------------------------------------------------------------------------
    // 3. A shadow-mode scan pass: compute everything, create nothing.
    // ---------------------------------------------------------------------------
    advance_to(&clock, base.selected_at)?;
    let shadow = RenewalController::new(
        repositories.clone(),
        service.clone(),
        RenewalControllerConfig {
            shadow_mode: true,
            ..Default::default()
        },
    );
    let report = shadow.scan_once().await?;
    println!(
        "\nshadow scan  @ {}: scanned {}, decisions {}, operations_created {}, shadowed {}",
        clock.now(),
        report.scanned,
        report.decisions.len(),
        report.operations_created,
        report.shadowed
    );

    // ---------------------------------------------------------------------------
    // 4. A real pass: the due lineage gets a durable, idempotent Renew op.
    // ---------------------------------------------------------------------------
    let controller = RenewalController::new(
        repositories.clone(),
        service.clone(),
        RenewalControllerConfig::default(),
    );
    let report = controller.scan_once().await?;
    println!(
        "live scan    @ {}: scanned {}, decisions {}, operations_created {}, leases_skipped {}",
        clock.now(),
        report.scanned,
        report.decisions.len(),
        report.operations_created,
        report.leases_skipped
    );

    let idempotency_key = format!("renewal:{lineage_id}:{version_id}");
    if let Some(stored) = repositories
        .operations
        .find_by_idempotency_key(&idempotency_key)
        .await?
    {
        println!(
            "created operation {} kind={} status={} idempotency_key=`{idempotency_key}`",
            stored.value.id,
            stored.value.kind.as_str(),
            stored.value.status.as_str()
        );
        debug_assert_eq!(stored.value.status, OperationStatus::Queued);
    }
    println!(
        "\nA worker (`acmex serve`, `acmex daemon` or `WorkflowEngine::spawn`)\npicks the operation up from here — the controller only decides."
    );

    Ok(())
}

fn print_decision(label: &str, decision: &RenewalDecision) {
    println!(
        "  {label:<26} priority={:<8} reason={:<24} should_create_operation={}",
        priority_label(decision.priority),
        reason_label(decision.reason),
        decision.should_create_operation(),
    );
}

/// Serde-compatible labels for the decision enums.
fn priority_label(priority: acmex::renewal::RenewalPriority) -> &'static str {
    match priority {
        acmex::renewal::RenewalPriority::Low => "low",
        acmex::renewal::RenewalPriority::Normal => "normal",
        acmex::renewal::RenewalPriority::High => "high",
        acmex::renewal::RenewalPriority::Urgent => "urgent",
        acmex::renewal::RenewalPriority::Critical => "critical",
    }
}

fn reason_label(reason: acmex::renewal::RenewalReason) -> &'static str {
    match reason {
        acmex::renewal::RenewalReason::NotYetDue => "not_yet_due",
        acmex::renewal::RenewalReason::SelectedAtReached => "selected_at_reached",
        acmex::renewal::RenewalReason::SafetyDeadlineReached => "safety_deadline_reached",
        acmex::renewal::RenewalReason::NoActiveVersion => "no_active_version",
    }
}

/// Moves the shared fake clock forward to `instant`.
fn advance_to(clock: &FakeClock, instant: Timestamp) -> Result<(), Box<dyn std::error::Error>> {
    let delta = instant.as_second() - clock.now().as_second();
    if delta > 0 {
        clock.advance_secs(delta);
    }
    Ok(())
}

/// An active version fixture. The decision calculator only reads
/// `not_before`/`not_after` here (plus the ids, for the stable jitter) —
/// an ARI-backed controller would instead derive windows from the chain.
fn active_version(
    id: VersionId,
    lineage_id: LineageId,
    identifiers: IdentifierSet,
) -> CertificateVersion {
    CertificateVersion {
        id,
        lineage_id,
        identifiers,
        certificate_chain_pem: "(demo fixture: not parsed without an ARI provider)".to_string(),
        serial: "00".to_string(),
        not_before: NOT_BEFORE.to_string(),
        not_after: NOT_AFTER.to_string(),
        issued_by: "demo-ca".to_string(),
        profile: None,
        key_ref: KeyRef::software(KeyId::new("key_demo").unwrap(), KeyAlgorithm::EcP256),
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state: VersionState::Active,
    }
}
