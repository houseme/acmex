//! Redis repository contract run (roadmap task T02).
//!
//! Executes the SAME backend-agnostic contract bodies as
//! `tests/repository_contract.rs` (intents, lineages/versions, operations,
//! leases, outbox, accounts — see `tests/common/repository_contract.rs`)
//! against `RepositorySet::redis`. A passing run is the multi-backend
//! evidence that the repository contract holds beyond memory/file.
//!
//! Precise scope of "all backends": the six shared contract bodies run
//! here. The following tests in `tests/repository_contract.rs` are
//! FILE-ONLY by design and deliberately do NOT run against redis:
//!
//! - legacy `.bin` FileStorage fix and bundle migration
//!   (`legacy_file_storage_list_round_trips`,
//!   `legacy_bundle_migration_runs_once_and_is_idempotent`,
//!   `legacy_bundle_migration_reports_corrupt_records`)
//! - file corruption detection
//!   (`file_corrupt_entity_is_an_explicit_error`)
//! - temp-file immunity (`file_temp_files_are_not_entities`)
//! - on-disk layout pinning (`file_layout_matches_spec`) and the
//!   file-rooted hostile-id traversal assertions
//!   (`accounts_file_hostile_ids`)
//! - the fake-clock scenarios that need the injectable memory clock
//!   (`lease_expiry_takeover_with_fake_clock`,
//!   `outbox_retry_delay_hides_event_until_next_attempt`); live redis
//!   lease expiry is covered by `tests/repository_redis_live.rs`.
//!
//! Configuration:
//!
//! ```text
//! ACMEX_TEST_REDIS_URL=redis://127.0.0.1:6379/15   # use a disposable DB index
//! ```
//!
//! Without that variable the run prints an explicit SKIP reason to stderr
//! and exits 77 — a skipped run is not a release pass (same convention as
//! `scripts/run_pebble_e2e.sh`). Tests write under the `acmex:v1:` key
//! prefix, so prefer a throwaway DB index or an ephemeral container.
#![cfg(feature = "redis")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "common/repository_contract.rs"]
mod repository_contract;

use acmex::repository::{RedisRepository, RepositorySet, SystemClock};
use repository_contract::{
    account_contract, intent_contract, lease_contract, lineage_version_contract,
    operation_contract, outbox_contract,
};

const SKIP_MESSAGE: &str = "SKIP: ACMEX_TEST_REDIS_URL is not set (e.g. \
redis://127.0.0.1:6379/15 — use a disposable DB index; the suite writes under \
the `acmex:test:*` prefix). A skipped Redis repository contract run is not a \
release pass.";

static TEST_PREFIX_COUNTER: AtomicU64 = AtomicU64::new(0);

fn redis_url_or_skip() -> String {
    match std::env::var("ACMEX_TEST_REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url.trim().to_string(),
        _ => {
            eprintln!("{SKIP_MESSAGE}");
            std::process::exit(77);
        }
    }
}

async fn redis_set() -> RepositorySet {
    let index = TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed);
    let prefix = format!("acmex:test:{}:{index}", std::process::id());
    RedisRepository::with_key_prefix(&redis_url_or_skip(), prefix, Arc::new(SystemClock))
        .await
        .map(RedisRepository::into_set)
        .expect("connect to redis at ACMEX_TEST_REDIS_URL")
}

#[tokio::test]
#[ignore = "requires ACMEX_TEST_REDIS_URL pointing at a disposable Redis DB"]
async fn intents_redis() {
    intent_contract(&redis_set().await).await;
}

#[tokio::test]
#[ignore = "requires ACMEX_TEST_REDIS_URL pointing at a disposable Redis DB"]
async fn lineage_versions_redis() {
    lineage_version_contract(&redis_set().await).await;
}

#[tokio::test]
#[ignore = "requires ACMEX_TEST_REDIS_URL pointing at a disposable Redis DB"]
async fn operations_redis() {
    operation_contract(&redis_set().await).await;
}

#[tokio::test]
#[ignore = "requires ACMEX_TEST_REDIS_URL pointing at a disposable Redis DB"]
async fn leases_redis() {
    lease_contract(&redis_set().await).await;
}

#[tokio::test]
#[ignore = "requires ACMEX_TEST_REDIS_URL pointing at a disposable Redis DB"]
async fn outbox_redis() {
    outbox_contract(&redis_set().await).await;
}

#[tokio::test]
#[ignore = "requires ACMEX_TEST_REDIS_URL pointing at a disposable Redis DB"]
async fn accounts_redis() {
    account_contract(&redis_set().await).await;
}
