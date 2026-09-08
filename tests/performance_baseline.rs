use std::time::Instant;

use acmex::domain::{CertificateIntent, IdentifierSet, IntentId, KeyRef, TenantId, VersionState};
use acmex::repository::{Clock, CreateOutcome, MemoryRepository};

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

/// Same workload as [`intent_scan_baseline_reports_elapsed_time`] against the
/// file backend: one insert per entity (atomic temp-file + fsync + rename)
/// followed by repeated scans, mirroring the periodic renewal sweep that
/// lists every intent. `scan_ms` reports the steady-state (warm) scan, i.e.
/// the fastest of three, and `cold_scan_ms` the very first one.
#[tokio::test]
#[ignore = "release baseline; run scripts/run_performance_baseline.sh to capture numbers"]
async fn file_backend_intent_scan_baseline_reports_elapsed_time() {
    let count: usize = std::env::var("ACMEX_PERF_INTENTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000);

    let dir = std::env::temp_dir().join(format!(
        "acmex-perf-file-baseline-{}-{}",
        std::process::id(),
        acmex::repository::SystemClock.now().as_millisecond()
    ));
    let repo = acmex::repository::FileRepository::new(&dir)
        .await
        .expect("open file repository");
    let set = repo.into_set();

    let insert_start = Instant::now();
    for index in 0..count {
        assert_eq!(
            set.intents.create(intent(index)).await.unwrap(),
            CreateOutcome::Created
        );
    }
    let insert_elapsed = insert_start.elapsed();

    let cold_scan_elapsed = {
        let scan_start = Instant::now();
        let all = set.intents.list().await.unwrap();
        assert_eq!(all.len(), count);
        scan_start.elapsed()
    };
    let mut warm_scans = Vec::new();
    for _ in 0..3 {
        let scan_start = Instant::now();
        let all = set.intents.list().await.unwrap();
        warm_scans.push(scan_start.elapsed());
        assert_eq!(all.len(), count);
    }
    let warm_scan_elapsed = warm_scans
        .iter()
        .min()
        .copied()
        .unwrap_or(cold_scan_elapsed);

    eprintln!(
        "acmex_perf_baseline_file intents={count} insert_ms={} scan_ms={} cold_scan_ms={} backend=file rust={} key_ref_shape={}",
        insert_elapsed.as_millis(),
        warm_scan_elapsed.as_millis(),
        cold_scan_elapsed.as_millis(),
        env!("CARGO_PKG_VERSION"),
        std::mem::size_of::<KeyRef>(),
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Same workload as [`file_backend_intent_scan_baseline_reports_elapsed_time`]
/// against the file backend opened in explicit [`FsyncMode::Interval`] mode
/// (opt-in group commit, Redis-AOF-`everysec` semantics): inserts complete
/// with an atomic rename and no fsync on the hot path; a background sweeper
/// fsyncs at most `ACMEX_PERF_FSYNC_INTERVAL_MS` (default 100) after each
/// write and dropping the store performs a final flush. The reported
/// `insert_ms` therefore excludes deferred fsync work by design — that
/// deferral against a bounded durability window is exactly what the mode
/// buys, never the default.
#[tokio::test]
#[ignore = "release baseline; run scripts/run_performance_baseline.sh to capture numbers"]
async fn file_backend_fsync_interval_baseline_reports_elapsed_time() {
    use std::time::Duration;

    use acmex::repository::{FileRepository, FsyncMode};

    let count: usize = std::env::var("ACMEX_PERF_INTENTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000);
    let interval = Duration::from_millis(
        std::env::var("ACMEX_PERF_FSYNC_INTERVAL_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100),
    );

    let dir = std::env::temp_dir().join(format!(
        "acmex-perf-file-fsync-interval-baseline-{}-{}",
        std::process::id(),
        acmex::repository::SystemClock.now().as_millisecond()
    ));
    let repo = FileRepository::with_mode(&dir, FsyncMode::Interval(interval))
        .await
        .expect("open file repository (fsync interval mode)");
    let set = repo.into_set();

    let insert_start = Instant::now();
    for index in 0..count {
        assert_eq!(
            set.intents.create(intent(index)).await.unwrap(),
            CreateOutcome::Created
        );
    }
    let insert_elapsed = insert_start.elapsed();

    let cold_scan_elapsed = {
        let scan_start = Instant::now();
        let all = set.intents.list().await.unwrap();
        assert_eq!(all.len(), count);
        scan_start.elapsed()
    };
    let mut warm_scans = Vec::new();
    for _ in 0..3 {
        let scan_start = Instant::now();
        let all = set.intents.list().await.unwrap();
        warm_scans.push(scan_start.elapsed());
        assert_eq!(all.len(), count);
    }
    let warm_scan_elapsed = warm_scans
        .iter()
        .min()
        .copied()
        .unwrap_or(cold_scan_elapsed);

    eprintln!(
        "acmex_perf_baseline_file_fsync_interval intents={count} interval_ms={} insert_ms={} scan_ms={} cold_scan_ms={} backend=file-fsync-interval rust={} key_ref_shape={}",
        interval.as_millis(),
        insert_elapsed.as_millis(),
        warm_scan_elapsed.as_millis(),
        cold_scan_elapsed.as_millis(),
        env!("CARGO_PKG_VERSION"),
        std::mem::size_of::<KeyRef>(),
    );

    drop(set);
    std::fs::remove_dir_all(&dir).ok();
}
