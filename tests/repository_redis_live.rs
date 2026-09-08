//! Live Redis repository evidence gate — `#[ignore]`d because they talk to a
//! real Redis server.
//!
//! These are the live counterparts of `tests/repository_contract.rs` for the
//! `redis` backend: intent CRUD with CAS conflict, lease expiry takeover on
//! an injected (virtual) clock, and the outbox append/retry/dead-letter
//! loop. Following the repo's "a skip is not a pass" culture, a missing
//! environment variable prints an explicit SKIP line — the run then counts
//! as *no evidence collected*, never as proof that the backend works.
//!
//! Configuration:
//!
//! ```text
//! ACMEX_TEST_REDIS_URL=redis://127.0.0.1:6379/15   # use a disposable DB index
//! ```
//!
//! Run: `cargo test --all-features --test repository_redis_live -- --ignored`
//! Tests write under the `acmex:v1:` key prefix with process-unique ids, but
//! they do not clean up (the public repository surface has no delete), so a
//! throwaway DB (`.../15`) or an ephemeral container is recommended.
#![cfg(feature = "redis")]

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use acmex::repository::{
    CasOutcome, Clock, CreateOutcome, FakeClock, LeaseOutcome, RedisRepository, RepositorySet,
};
use jiff::Timestamp;

const SKIP_MESSAGE: &str = "SKIP: set ACMEX_TEST_REDIS_URL (e.g. redis://127.0.0.1:6379/15 — \
use a disposable DB; tests write under the `acmex:v1:` prefix) to collect live \
Redis repository evidence";

fn redis_url() -> Option<String> {
    std::env::var("ACMEX_TEST_REDIS_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// A run-unique lease key so a leftover lock from a previous run (judged by
/// its own virtual clock) cannot leak into this run.
fn lease_key() -> String {
    format!("lineage/live-{}", Timestamp::now().as_millisecond())
}

#[tokio::test]
#[ignore = "requires a live Redis; set ACMEX_TEST_REDIS_URL"]
async fn live_intent_crud_cas_and_hostile_account_ids() {
    let Some(url) = redis_url() else {
        println!("{SKIP_MESSAGE}");
        return;
    };
    let set: RepositorySet = RedisRepository::connect(&url)
        .await
        .expect("connect")
        .into_set();

    let mut intent = acmex::domain::CertificateIntent {
        id: acmex::domain::IntentId::generate(),
        tenant_id: acmex::domain::TenantId::default_tenant(),
        identifiers: acmex::domain::IdentifierSet::parse(["live-redis.example.com"]).unwrap(),
        ca_policy: Default::default(),
        validation_policy: Default::default(),
        key_policy: Default::default(),
        renewal_policy: Default::default(),
        delivery_targets: Vec::new(),
        idempotency_key: format!("live-{}", Timestamp::now().as_millisecond()),
        generation: 1,
    };
    assert_eq!(
        set.intents.create(intent.clone()).await.unwrap(),
        CreateOutcome::Created
    );
    assert_eq!(
        set.intents.create(intent.clone()).await.unwrap(),
        CreateOutcome::AlreadyExists
    );

    let stored = set.intents.get(&intent.id).await.unwrap().expect("stored");
    assert_eq!(stored.value, intent);
    assert_eq!(stored.revision, 1);
    assert_eq!(stored.schema_version, 1);

    intent.generation = 2;
    assert_eq!(
        set.intents
            .update(stored.revision, intent.clone())
            .await
            .unwrap(),
        CasOutcome::Updated(2)
    );
    // A stale revision must lose against the (single, atomic) CAS script.
    assert_eq!(
        set.intents.update(stored.revision, intent).await.unwrap(),
        CasOutcome::Conflict { current: 2 }
    );
    assert_eq!(set.intents.list().await.unwrap().len(), 1);

    // Hostile account ids (colons, slashes, Unicode) round-trip safely.
    let account = acmex::domain::AccountRecord {
        id: format!(
            "ten_default:ca/../../live,ünïcode-{}",
            Timestamp::now().as_millisecond()
        ),
        tenant_id: acmex::domain::TenantId::default_tenant(),
        ca_id: "lets-encrypt".to_string(),
        directory_url: "https://example.com/dir".to_string(),
        account_url: Some("https://example.com/acct/live".to_string()),
        key_ref: acmex::domain::KeyRef::software(
            acmex::domain::KeyId::generate(),
            acmex::domain::KeyAlgorithm::EcP256,
        ),
        contacts: vec![],
        eab_bound: false,
        status: acmex::domain::AccountStatus::Active,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    };
    set.accounts.upsert(account.clone()).await.unwrap();
    set.accounts
        .upsert(acmex::domain::AccountRecord {
            account_url: Some("https://example.com/acct/live-2".to_string()),
            ..account.clone()
        })
        .await
        .unwrap();
    let stored = set
        .accounts
        .get(&account.id)
        .await
        .unwrap()
        .expect("hostile-id account stored");
    assert_eq!(
        stored.value.account_url.as_deref(),
        Some("https://example.com/acct/live-2")
    );
}

#[tokio::test]
#[ignore = "requires a live Redis; set ACMEX_TEST_REDIS_URL"]
async fn live_lease_expiry_takeover_with_injected_clock() {
    let Some(url) = redis_url() else {
        println!("{SKIP_MESSAGE}");
        return;
    };
    let clock = Arc::new(FakeClock::at(
        Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
    ));
    let set: RepositorySet = RedisRepository::with_clock(&url, clock.clone())
        .await
        .expect("connect")
        .into_set();
    let ttl = Duration::from_secs(10);
    let key = lease_key();

    let grant = match set.leases.acquire(&key, "worker-a", ttl).await.unwrap() {
        LeaseOutcome::Granted(grant) => grant,
        other => panic!("expected grant, got {other:?}"),
    };
    // A second worker is locked out while the lease is live.
    match set.leases.acquire(&key, "worker-b", ttl).await.unwrap() {
        LeaseOutcome::HeldByOther { owner, .. } => assert_eq!(owner, "worker-a"),
        other => panic!("expected held-by-other, got {other:?}"),
    }

    clock.advance_secs(60); // lease expired on the injected clock

    let takeover = match set.leases.acquire(&key, "worker-b", ttl).await.unwrap() {
        LeaseOutcome::Granted(grant) => grant,
        other => panic!("expired lease must be taken over, got {other:?}"),
    };
    assert!(
        takeover.fencing_token > grant.fencing_token,
        "fencing tokens must be strictly monotonic across takeover"
    );
    // The original owner cannot renew after the takeover.
    assert!(
        set.leases
            .renew(&key, "worker-a", grant.fencing_token, ttl)
            .await
            .unwrap()
            .is_none()
    );
    // The new owner can renew and then release.
    assert!(
        set.leases
            .renew(&key, "worker-b", takeover.fencing_token, ttl)
            .await
            .unwrap()
            .is_some()
    );
    set.leases
        .release(&key, "worker-b", takeover.fencing_token)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a live Redis; set ACMEX_TEST_REDIS_URL"]
async fn live_outbox_append_retry_and_dead_letter() {
    let Some(url) = redis_url() else {
        println!("{SKIP_MESSAGE}");
        return;
    };
    let clock = Arc::new(FakeClock::at(
        Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
    ));
    let set: RepositorySet = RedisRepository::with_clock(&url, clock.clone())
        .await
        .expect("connect")
        .into_set();

    // Assertions are relative to this run's sequences: the DB may hold
    // events from earlier runs (sequences are global INCR counters).
    let seq1 = set
        .outbox
        .append("operation.created", serde_json::json!({"live": 1}), None)
        .await
        .unwrap();
    let seq2 = set
        .outbox
        .append("operation.succeeded", serde_json::json!({"live": 1}), None)
        .await
        .unwrap();
    assert!(seq2 > seq1, "sequences must be monotonic");

    let pending = pending_sequences(&set, seq1, seq2).await;
    assert!(pending.contains(&seq1) && pending.contains(&seq2));
    // Default event ids follow the file-backend convention.
    let listed = set.outbox.list_pending(1000).await.unwrap();
    let first = listed.iter().find(|e| e.sequence == seq1).unwrap();
    assert_eq!(first.event_id, format!("evt_{seq1:012}"));

    set.outbox.mark_processed(seq1).await.unwrap();
    let pending = pending_sequences(&set, seq1, seq2).await;
    assert!(!pending.contains(&seq1), "processed events leave the queue");
    assert!(pending.contains(&seq2));

    // A past retry time keeps the event deliverable and records the attempt.
    let retry_at = clock
        .now()
        .checked_sub(jiff::Span::new().seconds(1))
        .unwrap();
    set.outbox
        .mark_failed(seq2, "webhook 500", Some(retry_at))
        .await
        .unwrap();
    let listed = set.outbox.list_pending(1000).await.unwrap();
    let failed = listed.iter().find(|e| e.sequence == seq2).unwrap();
    assert_eq!(failed.attempts, 1);
    assert_eq!(failed.last_error.as_deref(), Some("webhook 500"));

    // A future retry time hides the event until the clock advances.
    let retry_at = clock
        .now()
        .checked_add(jiff::Span::new().seconds(30))
        .unwrap();
    set.outbox
        .mark_failed(seq2, "webhook 503", Some(retry_at))
        .await
        .unwrap();
    assert!(
        !pending_sequences(&set, seq1, seq2).await.contains(&seq2),
        "event must wait for its next attempt time"
    );
    clock.advance_secs(31);
    assert!(pending_sequences(&set, seq1, seq2).await.contains(&seq2));

    set.outbox
        .dead_letter(seq2, "too many attempts")
        .await
        .unwrap();
    assert!(!pending_sequences(&set, seq1, seq2).await.contains(&seq2));
    set.outbox.requeue(seq2).await.unwrap();
    assert!(pending_sequences(&set, seq1, seq2).await.contains(&seq2));
}

async fn pending_sequences(
    set: &acmex::repository::RepositorySet,
    seq1: u64,
    seq2: u64,
) -> Vec<u64> {
    set.outbox
        .list_pending(1000)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.sequence)
        .filter(|s| *s == seq1 || *s == seq2)
        .collect()
}
