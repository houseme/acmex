//! Backend-agnostic repository contract bodies (roadmap task T02).
//!
//! Each `*_contract` function encodes the acceptance criteria every
//! repository backend must satisfy — create / get / list / duplicate / CAS,
//! the ready query and idempotency lookup, lease acquire / renew / release
//! fencing, outbox ordering and retry bookkeeping, and account upserts.
//!
//! They are executed against `RepositorySet::memory`/file by
//! `tests/repository_contract.rs` and against `RepositorySet::redis` by
//! `tests/repository_redis_contract.rs`, so one edit tightens the contract
//! on every backend at once.

use std::str::FromStr;
use std::time::Duration;

use acmex::domain::{
    AccountRecord, AccountStatus, CertificateIntent, CertificateLineage, CertificateVersion,
    IdentifierSet, KeyAlgorithm, KeyId, KeyRef, LineageId, OperationRecord, OperationStatus,
    OperationSubject, TenantId, VersionId, VersionState,
};
use acmex::repository::{CasOutcome, CreateOutcome, LeaseOutcome, RepositorySet};
use jiff::Timestamp;

pub fn sample_intent(id_suffix: &str) -> CertificateIntent {
    let mut intent = base_intent();
    intent.id = acmex::domain::IntentId::new(format!("int_test_{id_suffix}")).unwrap();
    intent
}

pub fn base_intent() -> CertificateIntent {
    CertificateIntent {
        id: acmex::domain::IntentId::generate(),
        tenant_id: TenantId::default_tenant(),
        identifiers: IdentifierSet::parse(["example.com"]).unwrap(),
        ca_policy: Default::default(),
        validation_policy: Default::default(),
        key_policy: Default::default(),
        renewal_policy: Default::default(),
        delivery_targets: Vec::new(),
        idempotency_key: "idem-1".to_string(),
        generation: 1,
    }
}

pub fn sample_version(lineage: &LineageId, state: VersionState) -> CertificateVersion {
    CertificateVersion {
        id: VersionId::generate(),
        lineage_id: lineage.clone(),
        identifiers: IdentifierSet::parse(["example.com"]).unwrap(),
        certificate_chain_pem: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"
            .to_string(),
        serial: "00ff".to_string(),
        not_before: "2026-01-01T00:00:00Z".to_string(),
        not_after: "2026-04-01T00:00:00Z".to_string(),
        issued_by: "test-ca".to_string(),
        profile: None,
        key_ref: KeyRef::software(KeyId::generate(), KeyAlgorithm::EcP256),
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state,
    }
}

// ---------------------------------------------------------------------------
// contract: intents
// ---------------------------------------------------------------------------

pub async fn intent_contract(set: &RepositorySet) {
    let intent = sample_intent("1");
    assert_eq!(
        set.intents.create(intent.clone()).await.unwrap(),
        CreateOutcome::Created
    );
    // duplicate create
    assert_eq!(
        set.intents.create(intent.clone()).await.unwrap(),
        CreateOutcome::AlreadyExists
    );
    // get
    let stored = set.intents.get(&intent.id).await.unwrap().expect("stored");
    assert_eq!(stored.value, intent);
    assert_eq!(stored.revision, 1);
    // list
    assert_eq!(set.intents.list().await.unwrap().len(), 1);
    // CAS success
    let mut updated = intent.clone();
    updated.generation = 2;
    assert_eq!(
        set.intents
            .update(stored.revision, updated.clone())
            .await
            .unwrap(),
        CasOutcome::Updated(2)
    );
    // CAS conflict with stale revision
    assert_eq!(
        set.intents.update(stored.revision, updated).await.unwrap(),
        CasOutcome::Conflict { current: 2 }
    );
}

// ---------------------------------------------------------------------------
// contract: lineages + versions
// ---------------------------------------------------------------------------

pub async fn lineage_version_contract(set: &RepositorySet) {
    let lineage_id = LineageId::generate();
    let lineage = CertificateLineage::new(
        lineage_id.clone(),
        TenantId::default_tenant(),
        acmex::domain::IntentId::generate(),
        IdentifierSet::parse(["example.com"]).unwrap(),
    );
    assert_eq!(
        set.lineages.create(lineage.clone()).await.unwrap(),
        CreateOutcome::Created
    );

    let v1 = sample_version(&lineage_id, VersionState::Active);
    assert_eq!(
        set.versions.create(v1.clone()).await.unwrap(),
        CreateOutcome::Created
    );
    assert_eq!(
        set.versions.create(v1.clone()).await.unwrap(),
        CreateOutcome::AlreadyExists
    );

    // activate via CAS on lineage
    let stored = set.lineages.get(&lineage_id).await.unwrap().unwrap();
    let mut activated = lineage.clone();
    activated.active_version_id = Some(v1.id.clone());
    assert!(matches!(
        set.lineages
            .update(stored.revision, activated)
            .await
            .unwrap(),
        CasOutcome::Updated(_)
    ));

    // list_by_lineage
    assert_eq!(
        set.versions
            .list_by_lineage(&lineage_id)
            .await
            .unwrap()
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------
// contract: operations (ready query, idempotency lookup)
// ---------------------------------------------------------------------------

pub async fn operation_contract(set: &RepositorySet) {
    let now = Timestamp::from_str("2026-01-01T00:00:00Z").unwrap();
    let mut record = OperationRecord::new_issue(
        acmex::domain::OperationId::generate(),
        OperationSubject::empty(),
        Some("idem-9".to_string()),
        Some("hash-9".to_string()),
        now,
    );
    assert_eq!(
        set.operations.create(record.clone()).await.unwrap(),
        CreateOutcome::Created
    );

    // ready query finds queued operations
    let ready = set.operations.list_ready(now, 10).await.unwrap();
    assert_eq!(ready.len(), 1);

    // waiting operation not ready before wake_at
    record = record
        .transition(OperationStatus::Running)
        .unwrap()
        .transition(OperationStatus::Waiting)
        .unwrap();
    record.wake_at = Some(now.checked_add(jiff::Span::new().seconds(60)).unwrap());
    let stored = set.operations.get(&record.id).await.unwrap().unwrap();
    set.operations
        .update(stored.revision, record.clone())
        .await
        .unwrap();
    assert!(set.operations.list_ready(now, 10).await.unwrap().is_empty());
    assert_eq!(
        set.operations
            .list_ready(now.checked_add(jiff::Span::new().seconds(120)).unwrap(), 10)
            .await
            .unwrap()
            .len(),
        1
    );

    // idempotency lookup
    let found = set
        .operations
        .find_by_idempotency("idem-9", "hash-9")
        .await
        .unwrap()
        .expect("found by idempotency");
    assert_eq!(found.value.id, record.id);

    // terminal operations are never ready
    let stored = set.operations.get(&record.id).await.unwrap().unwrap();
    let done = record
        .transition(OperationStatus::Running)
        .unwrap()
        .transition(OperationStatus::Succeeded)
        .unwrap();
    set.operations.update(stored.revision, done).await.unwrap();
    let later = now.checked_add(jiff::Span::new().hours(2)).unwrap();
    assert!(
        set.operations
            .list_ready(later, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// contract: leases
// ---------------------------------------------------------------------------

pub async fn lease_contract(set: &RepositorySet) {
    let ttl = Duration::from_secs(30);

    // acquire / conflict / release
    let granted = match set.leases.acquire("op/1", "worker-a", ttl).await.unwrap() {
        LeaseOutcome::Granted(grant) => grant,
        other => panic!("expected grant, got {other:?}"),
    };
    assert!(granted.fencing_token > 0);
    match set.leases.acquire("op/1", "worker-b", ttl).await.unwrap() {
        LeaseOutcome::HeldByOther { owner, .. } => assert_eq!(owner, "worker-a"),
        other => panic!("expected held-by-other, got {other:?}"),
    }

    // renew by the owner works
    assert!(
        set.leases
            .renew("op/1", "worker-a", granted.fencing_token, ttl)
            .await
            .unwrap()
            .is_some()
    );

    // release with wrong token is a no-op
    set.leases
        .release("op/1", "worker-a", granted.fencing_token + 999)
        .await
        .unwrap();
    match set.leases.acquire("op/1", "worker-b", ttl).await.unwrap() {
        LeaseOutcome::HeldByOther { .. } => {}
        other => panic!("expected still held, got {other:?}"),
    }

    // proper release frees the key, takeover bumps the fencing token
    set.leases
        .release("op/1", "worker-a", granted.fencing_token)
        .await
        .unwrap();
    let second = match set.leases.acquire("op/1", "worker-b", ttl).await.unwrap() {
        LeaseOutcome::Granted(grant) => grant,
        other => panic!("expected re-grant, got {other:?}"),
    };
    assert!(
        second.fencing_token > granted.fencing_token,
        "fencing token must be monotonic"
    );
}

// ---------------------------------------------------------------------------
// contract: outbox
// ---------------------------------------------------------------------------

pub async fn outbox_contract(set: &RepositorySet) {
    let seq1 = set
        .outbox
        .append("operation.created", serde_json::json!({"id": 1}), None)
        .await
        .unwrap();
    let seq2 = set
        .outbox
        .append("operation.succeeded", serde_json::json!({"id": 1}), None)
        .await
        .unwrap();
    assert!(seq2 > seq1, "sequences must be monotonic");

    let pending = set.outbox.list_pending(10).await.unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].sequence, seq1);
    assert_eq!(pending[0].event_id, format!("evt_{seq1:012}"));

    set.outbox.mark_processed(seq1).await.unwrap();
    let pending = set.outbox.list_pending(10).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].sequence, seq2);

    let retry_at = set
        .clock
        .now()
        .checked_sub(jiff::Span::new().seconds(1))
        .unwrap();
    set.outbox
        .mark_failed(seq2, "webhook 500", Some(retry_at))
        .await
        .unwrap();
    let pending = set.outbox.list_pending(10).await.unwrap();
    assert_eq!(pending[0].attempts, 1);
    assert_eq!(pending[0].last_error.as_deref(), Some("webhook 500"));

    set.outbox
        .dead_letter(seq2, "too many attempts")
        .await
        .unwrap();
    assert!(set.outbox.list_pending(10).await.unwrap().is_empty());
    set.outbox.requeue(seq2).await.unwrap();
    let pending = set.outbox.list_pending(10).await.unwrap();
    assert_eq!(pending.len(), 1);
    // Manual replay restarts the retry budget: `attempts` is reset to 0 on
    // every backend (redis, memory, file), so the replayed event gets a full
    // retry allowance again.
    assert_eq!(pending[0].attempts, 0);
    assert_eq!(pending[0].last_error, None);
}

// ---------------------------------------------------------------------------
// contract: accounts (upsert)
// ---------------------------------------------------------------------------

pub async fn account_contract(set: &RepositorySet) {
    let account = AccountRecord {
        id: "ten_default:lets-encrypt".to_string(),
        tenant_id: TenantId::default_tenant(),
        ca_id: "lets-encrypt".to_string(),
        directory_url: "https://example.com/dir".to_string(),
        account_url: None,
        key_ref: KeyRef::software(KeyId::generate(), KeyAlgorithm::EcP256),
        contacts: vec![],
        eab_bound: false,
        status: AccountStatus::Active,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    };
    set.accounts.upsert(account.clone()).await.unwrap();
    set.accounts
        .upsert(AccountRecord {
            account_url: Some("https://example.com/acct/1".to_string()),
            ..account.clone()
        })
        .await
        .unwrap();
    let stored = set
        .accounts
        .get(&account.id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(
        stored.value.account_url.as_deref(),
        Some("https://example.com/acct/1")
    );
    assert_eq!(set.accounts.list().await.unwrap().len(), 1);
}
