use std::time::Instant;

use acmex::domain::{CertificateIntent, IdentifierSet, IntentId, KeyRef, TenantId, VersionState};
use acmex::repository::{CreateOutcome, MemoryRepository};

fn intent(index: usize) -> CertificateIntent {
    CertificateIntent {
        id: IntentId::new(format!("int_perf_{index:06}")).unwrap(),
        tenant_id: TenantId::default_tenant(),
        identifiers: IdentifierSet::parse([format!("perf-{index}.example.com")]).unwrap(),
        ca_policy: Default::default(),
        validation_policy: Default::default(),
        key_policy: Default::default(),
        renewal_policy: Default::default(),
        delivery_targets: Vec::new(),
        idempotency_key: format!("perf-{index}"),
        generation: 1,
    }
}

#[tokio::test]
#[ignore = "release baseline; run scripts/run_performance_baseline.sh to capture numbers"]
async fn intent_scan_baseline_reports_elapsed_time() {
    let count: usize = std::env::var("ACMEX_PERF_INTENTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000);
    let set = MemoryRepository::new().into_set();

    let insert_start = Instant::now();
    for index in 0..count {
        assert_eq!(
            set.intents.create(intent(index)).await.unwrap(),
            CreateOutcome::Created
        );
    }
    let insert_elapsed = insert_start.elapsed();

    let scan_start = Instant::now();
    let all = set.intents.list().await.unwrap();
    let scan_elapsed = scan_start.elapsed();

    assert_eq!(all.len(), count);
    eprintln!(
        "acmex_perf_baseline intents={count} insert_ms={} scan_ms={} backend=memory rust={} key_ref_shape={}",
        insert_elapsed.as_millis(),
        scan_elapsed.as_millis(),
        env!("CARGO_PKG_VERSION"),
        std::mem::size_of::<KeyRef>(),
    );

    let _ = VersionState::Active;
}
