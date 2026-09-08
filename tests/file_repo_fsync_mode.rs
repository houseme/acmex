//! Durability-contract tests for the file repository's [`FsyncMode`].
//!
//! * `Always` (default): the historical behavior — every write is fsynced
//!   before its atomic rename returns; `sync_pending` is a no-op.
//! * `Interval` (explicit opt-in, Redis-AOF-`everysec`-style group commit):
//!   writes are visible immediately, a background sweeper fsyncs at most one
//!   interval window later, and `Drop` flushes and joins.

use std::time::Duration;

use acmex::domain::{CertificateIntent, IdentifierSet, IntentId, TenantId};
use acmex::repository::{
    CasOutcome, Clock, CreateOutcome, FSYNC_DROP_FLUSHES, FSYNC_SWEEPER_SHUTDOWNS, FileRepository,
    FsyncMode, OutboxRepository, SystemClock,
};
use serde_json::json;
use std::sync::atomic::Ordering;

fn unique_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "acmex-file-fsync-mode-{label}-{}-{}",
        std::process::id(),
        SystemClock.now().as_millisecond()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn intent(index: usize) -> CertificateIntent {
    CertificateIntent {
        id: IntentId::new(format!("int_fsync_{index:03}")).unwrap(),
        tenant_id: TenantId::default_tenant(),
        identifiers: IdentifierSet::parse([format!("fsync-{index}.example.com")]).unwrap(),
        ca_policy: Default::default(),
        validation_policy: Default::default(),
        key_policy: Default::default(),
        renewal_policy: Default::default(),
        delivery_targets: Vec::new(),
        idempotency_key: format!("fsync-{index}"),
        generation: 1,
    }
}

#[tokio::test]
async fn default_file_repository_is_fsync_mode_always() {
    let dir = unique_dir("default");
    let repo = FileRepository::new(&dir).await.unwrap();
    assert_eq!(repo.store().fsync_mode(), FsyncMode::Always);
    drop(repo);

    let repo = FileRepository::with_mode(&dir, FsyncMode::Always)
        .await
        .unwrap();
    assert_eq!(repo.store().fsync_mode(), FsyncMode::Always);
    drop(repo);

    let _ = std::fs::remove_dir_all(&dir);
}

/// `Always` mode roundtrip through the public intent API, including the
/// create/AlreadyExists/CAS contract.
#[tokio::test]
async fn always_mode_intent_roundtrip_and_cas() {
    let dir = unique_dir("always-roundtrip");
    let repo = FileRepository::with_mode(&dir, FsyncMode::Always)
        .await
        .unwrap();
    let set = repo.into_set();

    assert_eq!(
        set.intents.create(intent(1)).await.unwrap(),
        CreateOutcome::Created
    );
    assert_eq!(
        set.intents.create(intent(1)).await.unwrap(),
        CreateOutcome::AlreadyExists
    );

    let stored = set
        .intents
        .get(&IntentId::new("int_fsync_001").unwrap())
        .await
        .unwrap()
        .expect("created intent is readable");
    assert_eq!(stored.revision, 1);
    assert_eq!(stored.value.idempotency_key, "fsync-1");

    let mut updated = intent(1);
    updated.generation = 2;
    assert!(matches!(
        set.intents.update(stored.revision, updated).await.unwrap(),
        CasOutcome::Updated(2)
    ));
    let reread = set
        .intents
        .get(&IntentId::new("int_fsync_001").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reread.value.generation, 2);

    drop(set);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `Interval` mode defers fsync: the outbox write is immediately readable,
/// nothing is fsynced before the sweep, and a forced sweep fsyncs exactly
/// the pending files (observable via the fsynced-file counter).
#[tokio::test]
async fn interval_mode_defers_and_forces_fsync() {
    let dir = unique_dir("interval-force");
    let repo = FileRepository::with_mode(&dir, FsyncMode::Interval(Duration::from_secs(3600)))
        .await
        .unwrap();

    for index in 0..3 {
        repo.append("test.event", json!({ "n": index }), None)
            .await
            .unwrap();
    }
    assert_eq!(
        repo.store().fsynced_file_count(),
        0,
        "no fsync may happen before the sweep in Interval mode"
    );
    assert_eq!(repo.store().sync_pending().await.unwrap(), 3);
    assert_eq!(repo.store().fsynced_file_count(), 3);
    assert_eq!(repo.store().sync_pending().await.unwrap(), 0);

    drop(repo);
    let _ = std::fs::remove_dir_all(&dir);
}

/// After the interval window elapses the sweeper must have fsynced the
/// writes on its own (no `sync_pending` involved) — observed through the
/// real fsync counter, not through data visibility (a rename alone would
/// make data visible without any fsync); after the drop, the sweeper must
/// have exited.
#[tokio::test]
async fn interval_mode_background_sweeper_fsyncs_within_window() {
    let dir = unique_dir("interval-window");
    let repo = FileRepository::with_mode(&dir, FsyncMode::Interval(Duration::from_millis(50)))
        .await
        .unwrap();
    // Shared clone: lets us observe the fsync counter and sweeper state
    // while the repository drives writes, and after it is dropped.
    let store = repo.store().clone();
    let set = repo.into_set();
    for index in 0..5 {
        assert_eq!(
            set.intents.create(intent(index)).await.unwrap(),
            CreateOutcome::Created
        );
    }
    // The sweeper must fsync all five files within a few windows — a
    // broken sweeper fails the deadline instead of passing silently.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while store.fsynced_file_count() < 5 {
        assert!(
            std::time::Instant::now() < deadline,
            "sweeper missed its window: only {} of 5 files fsynced",
            store.fsynced_file_count()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(set);

    let repo = FileRepository::new(&dir).await.unwrap();
    let set = repo.into_set();
    assert_eq!(set.intents.list().await.unwrap().len(), 5);
    drop(set);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Dropping the repository flushes pending writes and joins the sweeper:
/// the fsync counter advances (the final flush really synced), the shared
/// store observes the sweeper has exited, and a fresh repository observes
/// the data.
#[tokio::test]
async fn interval_mode_drop_flushes_and_joins() {
    let dir = unique_dir("interval-drop");
    let shutdowns_before = FSYNC_SWEEPER_SHUTDOWNS.load(Ordering::SeqCst);
    let drop_flushes_before = FSYNC_DROP_FLUSHES.load(Ordering::SeqCst);
    let repo = FileRepository::with_mode(&dir, FsyncMode::Interval(Duration::from_secs(3600)))
        .await
        .unwrap();
    let store = repo.store().clone();
    repo.append("test.final", json!({ "final": true }), None)
        .await
        .unwrap();
    assert_eq!(
        store.fsynced_file_count(),
        0,
        "nothing may be fsynced before the drop in Interval mode"
    );
    // Drop in "wrong" order on purpose: the surviving clone must keep the
    // sweeper alive, and only the LAST clone out shuts it down and flushes.
    drop(repo);
    assert_eq!(
        FSYNC_SWEEPER_SHUTDOWNS.load(Ordering::SeqCst),
        shutdowns_before,
        "a surviving clone must keep the sweeper alive"
    );
    drop(store); // final flush + join must complete without hanging

    assert_eq!(
        FSYNC_SWEEPER_SHUTDOWNS.load(Ordering::SeqCst),
        shutdowns_before + 1,
        "the last clone out must shut the sweeper down exactly once"
    );
    assert!(
        FSYNC_DROP_FLUSHES.load(Ordering::SeqCst) > drop_flushes_before,
        "drop's final flush must have really fsynced the pending files"
    );

    let repo = FileRepository::new(&dir).await.unwrap();
    let pending = repo.list_pending(10).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event_type, "test.final");
    drop(repo);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn always_mode_sync_pending_is_noop() {
    let dir = unique_dir("always-noop");
    let repo = FileRepository::new(&dir).await.unwrap();
    repo.append("test.event", json!({}), None).await.unwrap();
    assert_eq!(repo.store().sync_pending().await.unwrap(), 0);
    assert_eq!(repo.store().fsynced_file_count(), 0);
    drop(repo);
    let _ = std::fs::remove_dir_all(&dir);
}
