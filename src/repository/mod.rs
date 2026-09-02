//! Aggregate repositories, persistence primitives and the `RepositorySet`.
//!
//! The repository layer gives the application service aggregate-level
//! persistence (intents, lineages, versions, operations, challenge leases,
//! deployments, accounts, outbox events) with:
//!
//! * **Revisions** — every entity carries a monotonically increasing
//!   [`Revision`]; mutations go through compare-and-set ([`CasOutcome`]) so
//!   concurrent updates are detected instead of silently lost.
//! * **Leases** — [`LeaseManager`] grants exclusive, expiring leases with
//!   fencing tokens for multi-worker safety.
//! * **Outbox** — events are appended atomically with state changes and
//!   consumed at-least-once.
//!
//! Two backends are provided: [`memory::MemoryRepository`] (reference
//! implementation) and [`file::FileRepository`] (atomic JSON files). A
//! Redis implementation follows the same traits (roadmap T02 follow-up);
//! the trait surface is frozen for v0.9.0.
//!
//! Business code never concatenates storage keys (`cert:<domains>`) — it
//! talks to aggregates by typed IDs.

pub mod clock;
pub mod file;
pub mod memory;
pub mod migration;
pub mod secret_store;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use jiff::Timestamp;
use std::str::FromStr;

use crate::domain::{
    AccountRecord, CertificateIntent, CertificateLineage, CertificateVersion, ChallengeLease,
    DeploymentRecord, OperationId, OperationRecord, OperationStatus,
};
use crate::error::{AcmeError, Result};

pub use clock::{Clock, FakeClock, SystemClock};
pub use file::FileRepository;
pub use memory::MemoryRepository;
pub use migration::{
    LegacyBundleMigrator, MigrationMode, MigrationOutcome, MigrationPlanEntry, MigrationReport,
    MigrationStatus,
};
pub use secret_store::FileSecretStore;

/// Optimistic-concurrency revision of a stored entity.
pub type Revision = u64;

/// Monotonic fencing token guarding leased writes.
pub type FencingToken = u64;

/// An entity together with its persistence metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Versioned<T> {
    /// The entity value.
    pub value: T,
    /// Current revision (incremented on every accepted update).
    pub revision: Revision,
    /// Schema version of the stored entity shape.
    pub schema_version: u32,
    /// When the entity was first stored.
    pub created_at: Timestamp,
    /// When the entity was last updated.
    pub updated_at: Timestamp,
}

/// Outcome of an idempotent create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    /// The entity was created.
    Created,
    /// An entity with the same identity already exists.
    AlreadyExists,
}

/// Outcome of a compare-and-set update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasOutcome {
    /// The update was applied; contains the new revision.
    Updated(Revision),
    /// The expected revision was stale; `current` is the actual revision.
    Conflict { current: Revision },
}

impl CasOutcome {
    /// unwrap helper: error on conflict.
    pub fn expect_updated(self) -> Result<Revision> {
        match self {
            Self::Updated(rev) => Ok(rev),
            Self::Conflict { current } => Err(AcmeError::Storage(format!(
                "revision conflict (current revision is {current})"
            ))),
        }
    }
}

/// A granted lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrant {
    /// The leased key.
    pub key: String,
    /// Owner identity (usually a worker instance id).
    pub owner: String,
    /// Monotonic token; writes stamped with a stale token must be rejected.
    pub fencing_token: FencingToken,
    /// When the lease expires unless renewed.
    pub expires_at: Timestamp,
}

/// Outcome of a lease acquisition attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseOutcome {
    /// The lease was granted.
    Granted(LeaseGrant),
    /// Another owner holds a non-expired lease.
    HeldByOther {
        /// Current holder.
        owner: String,
        /// When their lease expires.
        expires_at: Timestamp,
    },
}

/// Exclusive, expiring leases with fencing tokens.
#[async_trait]
pub trait LeaseManager: Send + Sync {
    /// Acquires `key` for `owner` with the given TTL, unless held by an
    /// unexpired lease of another owner. Expired leases are taken over with
    /// a new (higher) fencing token.
    async fn acquire(&self, key: &str, owner: &str, ttl: Duration) -> Result<LeaseOutcome>;

    /// Renews a held lease; returns `None` when the lease was lost
    /// (expired and taken over).
    async fn renew(
        &self,
        key: &str,
        owner: &str,
        fencing_token: FencingToken,
        ttl: Duration,
    ) -> Result<Option<LeaseGrant>>;

    /// Releases a held lease. Releasing with a stale token is a no-op.
    async fn release(&self, key: &str, owner: &str, fencing_token: FencingToken) -> Result<()>;
}

/// An outbox event awaiting at-least-once delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxEvent {
    /// Sequence number, assigned by the repository (ordered).
    pub sequence: u64,
    /// Stable event id for consumer deduplication.
    pub event_id: String,
    /// Event type (e.g. `operation.succeeded`).
    pub event_type: String,
    /// Event payload (must not contain secrets).
    pub payload: Value,
    /// When the event was appended.
    pub created_at: Timestamp,
    /// Delivery attempts so far.
    pub attempts: u32,
    /// Last delivery error, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Earliest retry time after a failed delivery attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<Timestamp>,
    /// Whether delivery succeeded.
    pub processed: bool,
    /// Whether the event exhausted retries and awaits operator replay.
    #[serde(default)]
    pub dead_lettered: bool,
}

/// Append-only event outbox (at-least-once delivery).
#[async_trait]
pub trait OutboxRepository: Send + Sync {
    /// Appends an event; returns the assigned sequence.
    async fn append(
        &self,
        event_type: &str,
        payload: Value,
        event_id: Option<String>,
    ) -> Result<u64>;

    /// Returns up to `limit` unprocessed events in sequence order.
    async fn list_pending(&self, limit: usize) -> Result<Vec<OutboxEvent>>;

    /// Marks an event delivered.
    async fn mark_processed(&self, sequence: u64) -> Result<()>;

    /// Records a failed delivery attempt with its error.
    async fn mark_failed(
        &self,
        sequence: u64,
        error: &str,
        next_attempt_at: Option<Timestamp>,
    ) -> Result<()>;

    /// Marks an event as dead-lettered after exhausting retries.
    async fn dead_letter(&self, sequence: u64, reason: &str) -> Result<()>;

    /// Requeues a dead-lettered event for manual replay.
    async fn requeue(&self, sequence: u64) -> Result<()>;
}

/// Intent aggregate persistence.
#[async_trait]
pub trait IntentRepository: Send + Sync {
    /// Creates an intent; `AlreadyExists` when the id is taken.
    async fn create(&self, intent: CertificateIntent) -> Result<CreateOutcome>;
    /// Loads an intent by id.
    async fn get(
        &self,
        id: &crate::domain::IntentId,
    ) -> Result<Option<Versioned<CertificateIntent>>>;
    /// Compare-and-set update.
    async fn update(
        &self,
        expected_revision: Revision,
        intent: CertificateIntent,
    ) -> Result<CasOutcome>;
    /// Lists all intents ordered by id.
    async fn list(&self) -> Result<Vec<Versioned<CertificateIntent>>>;
}

/// Lineage aggregate persistence.
#[async_trait]
pub trait LineageRepository: Send + Sync {
    /// Creates a lineage.
    async fn create(&self, lineage: CertificateLineage) -> Result<CreateOutcome>;
    /// Loads a lineage by id.
    async fn get(
        &self,
        id: &crate::domain::LineageId,
    ) -> Result<Option<Versioned<CertificateLineage>>>;
    /// Compare-and-set update (used for the atomic active-version switch).
    async fn update(
        &self,
        expected_revision: Revision,
        lineage: CertificateLineage,
    ) -> Result<CasOutcome>;
    /// Lists all lineages ordered by id.
    async fn list(&self) -> Result<Vec<Versioned<CertificateLineage>>>;
}

/// Immutable certificate version persistence.
#[async_trait]
pub trait VersionRepository: Send + Sync {
    /// Creates a version; `AlreadyExists` when the id is taken.
    async fn create(&self, version: CertificateVersion) -> Result<CreateOutcome>;
    /// Loads a version by id.
    async fn get(
        &self,
        id: &crate::domain::VersionId,
    ) -> Result<Option<Versioned<CertificateVersion>>>;
    /// Compare-and-set update — only lifecycle state transitions are
    /// legal (issuance fields are immutable; enforced by the domain).
    async fn update(
        &self,
        expected_revision: Revision,
        version: CertificateVersion,
    ) -> Result<CasOutcome>;
    /// Lists all versions of a lineage, oldest first.
    async fn list_by_lineage(
        &self,
        lineage_id: &crate::domain::LineageId,
    ) -> Result<Vec<Versioned<CertificateVersion>>>;
}

/// Durable operation persistence.
#[async_trait]
pub trait OperationRepository: Send + Sync {
    /// Creates an operation.
    async fn create(&self, operation: OperationRecord) -> Result<CreateOutcome>;
    /// Loads an operation by id.
    async fn get(&self, id: &OperationId) -> Result<Option<Versioned<OperationRecord>>>;
    /// Compare-and-set update.
    async fn update(
        &self,
        expected_revision: Revision,
        operation: OperationRecord,
    ) -> Result<CasOutcome>;
    /// Returns up to `limit` operations that are ready to run at `now`
    /// (non-terminal, `wake_at` passed), ordered by creation.
    async fn list_ready(
        &self,
        now: Timestamp,
        limit: usize,
    ) -> Result<Vec<Versioned<OperationRecord>>>;
    /// Lists operations filtered by status, ordered by creation.
    async fn list_by_status(
        &self,
        status: OperationStatus,
        limit: usize,
    ) -> Result<Vec<Versioned<OperationRecord>>>;
    /// Finds an operation by idempotency key and request hash (dedup).
    async fn find_by_idempotency(
        &self,
        idempotency_key: &str,
        request_hash: &str,
    ) -> Result<Option<Versioned<OperationRecord>>>;
    /// Finds an operation by idempotency key regardless of request hash.
    async fn find_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<Versioned<OperationRecord>>>;
}

/// Challenge lease persistence.
#[async_trait]
pub trait ChallengeLeaseRepository: Send + Sync {
    /// Creates a lease.
    async fn create(&self, lease: ChallengeLease) -> Result<CreateOutcome>;
    /// Loads a lease by id.
    async fn get(
        &self,
        id: &crate::domain::ChallengeLeaseId,
    ) -> Result<Option<Versioned<ChallengeLease>>>;
    /// Compare-and-set update.
    async fn update(
        &self,
        expected_revision: Revision,
        lease: ChallengeLease,
    ) -> Result<CasOutcome>;
    /// Lists leases that still need cleanup (`active`, `cleanup_pending`
    /// or `cleanup_failed`).
    async fn list_needing_cleanup(&self) -> Result<Vec<Versioned<ChallengeLease>>>;
}

/// Challenge session persistence.
#[async_trait]
pub trait ChallengeSessionRepository: Send + Sync {
    /// Creates a session.
    async fn create(&self, session: crate::challenge::ChallengeSession) -> Result<CreateOutcome>;
    /// Loads a session by id.
    async fn get(&self, id: &str) -> Result<Option<Versioned<crate::challenge::ChallengeSession>>>;
    /// Compare-and-set update.
    async fn update(
        &self,
        expected_revision: Revision,
        session: crate::challenge::ChallengeSession,
    ) -> Result<CasOutcome>;
    /// All sessions of one operation.
    async fn list_by_operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Vec<Versioned<crate::challenge::ChallengeSession>>>;
}

/// Deployment persistence.
#[async_trait]
pub trait DeploymentRepository: Send + Sync {
    /// Creates a deployment.
    async fn create(&self, deployment: DeploymentRecord) -> Result<CreateOutcome>;
    /// Loads a deployment by id.
    async fn get(
        &self,
        id: &crate::domain::DeploymentId,
    ) -> Result<Option<Versioned<DeploymentRecord>>>;
    /// Compare-and-set update.
    async fn update(
        &self,
        expected_revision: Revision,
        deployment: DeploymentRecord,
    ) -> Result<CasOutcome>;
    /// Lists deployments for a version.
    async fn list_by_version(
        &self,
        version_id: &crate::domain::VersionId,
    ) -> Result<Vec<Versioned<DeploymentRecord>>>;
    /// Lists deployments for a lineage.
    async fn list_by_lineage(
        &self,
        lineage_id: &crate::domain::LineageId,
    ) -> Result<Vec<Versioned<DeploymentRecord>>>;
}

/// Account persistence.
#[async_trait]
pub trait AccountRepository: Send + Sync {
    /// Inserts or updates an account keyed by its composite id.
    async fn upsert(&self, account: AccountRecord) -> Result<()>;
    /// Loads an account by composite id.
    async fn get(&self, id: &str) -> Result<Option<Versioned<AccountRecord>>>;
    /// Lists all accounts.
    async fn list(&self) -> Result<Vec<Versioned<AccountRecord>>>;
}

/// One migrated legacy record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationManifestEntry {
    /// The legacy storage key (e.g. `cert:a.example.com`).
    pub source_key: String,
    /// SHA-256 of the legacy record bytes (idempotency anchor).
    pub source_hash: String,
    /// Lineage created for the record.
    pub lineage_id: crate::domain::LineageId,
    /// Version created for the record.
    pub version_id: crate::domain::VersionId,
    /// Key under which the private key was stored in the secret store.
    pub key_id: crate::domain::KeyId,
    /// When the migration happened.
    pub migrated_at: Timestamp,
}

/// Persistence for migration manifests (idempotency + audit).
#[async_trait]
pub trait MigrationManifestStore: Send + Sync {
    /// Appends a manifest entry (idempotent per `source_key`).
    async fn save_entry(&self, entry: MigrationManifestEntry) -> Result<()>;
    /// All manifest entries.
    async fn entries(&self) -> Result<Vec<MigrationManifestEntry>>;
}

/// The complete persistence surface used by application services.
///
/// Cheap to clone; all members are shared handles.
#[derive(Clone)]
pub struct RepositorySet {
    /// Backend identifier used as the `backend` metric label
    /// (`"memory"`, `"file"`, ...).
    pub backend: &'static str,
    /// Intents.
    pub intents: Arc<dyn IntentRepository>,
    /// Lineages.
    pub lineages: Arc<dyn LineageRepository>,
    /// Certificate versions.
    pub versions: Arc<dyn VersionRepository>,
    /// Operations.
    pub operations: Arc<dyn OperationRepository>,
    /// Challenge leases.
    pub challenge_leases: Arc<dyn ChallengeLeaseRepository>,
    /// Challenge sessions.
    pub challenge_sessions: Arc<dyn ChallengeSessionRepository>,
    /// Deployments.
    pub deployments: Arc<dyn DeploymentRepository>,
    /// CA accounts.
    pub accounts: Arc<dyn AccountRepository>,
    /// Event outbox.
    pub outbox: Arc<dyn OutboxRepository>,
    /// Distributed leases.
    pub leases: Arc<dyn LeaseManager>,
    /// Migration manifests.
    pub manifests: Arc<dyn MigrationManifestStore>,
    /// The clock used by this repository (virtualizable in tests).
    pub clock: Arc<dyn Clock>,
}

impl RepositorySet {
    /// Returns a repository set that records failed repository calls in
    /// `acmex_repository_errors_total{backend,operation}`.
    ///
    /// The wrapper sits at the trait-object boundary, so all memory/file/redis
    /// compatible backends and aggregate repositories share one observability
    /// path instead of scattering metrics calls through workflow code.
    pub fn observe_errors(self, metrics: crate::metrics::SharedMetrics) -> Self {
        let backend = self.backend;
        Self {
            backend,
            intents: Arc::new(ObservedRepository::new(
                self.intents,
                backend,
                metrics.clone(),
            )),
            lineages: Arc::new(ObservedRepository::new(
                self.lineages,
                backend,
                metrics.clone(),
            )),
            versions: Arc::new(ObservedRepository::new(
                self.versions,
                backend,
                metrics.clone(),
            )),
            operations: Arc::new(ObservedRepository::new(
                self.operations,
                backend,
                metrics.clone(),
            )),
            challenge_leases: Arc::new(ObservedRepository::new(
                self.challenge_leases,
                backend,
                metrics.clone(),
            )),
            challenge_sessions: Arc::new(ObservedRepository::new(
                self.challenge_sessions,
                backend,
                metrics.clone(),
            )),
            deployments: Arc::new(ObservedRepository::new(
                self.deployments,
                backend,
                metrics.clone(),
            )),
            accounts: Arc::new(ObservedRepository::new(
                self.accounts,
                backend,
                metrics.clone(),
            )),
            outbox: Arc::new(ObservedRepository::new(
                self.outbox,
                backend,
                metrics.clone(),
            )),
            leases: Arc::new(ObservedRepository::new(
                self.leases,
                backend,
                metrics.clone(),
            )),
            manifests: Arc::new(ObservedRepository::new(self.manifests, backend, metrics)),
            clock: self.clock,
        }
    }
}

/// Closed operation categories for `acmex_repository_errors_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryOperation {
    /// Single-entity lookups and point reads.
    Read,
    /// Creates and ordinary writes.
    Write,
    /// Lists and filtered scans.
    Scan,
    /// Compare-and-set, lease and fencing mutations.
    Cas,
    /// Legacy migration manifest reads/writes.
    Migrate,
}

impl RepositoryOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Scan => "scan",
            Self::Cas => "cas",
            Self::Migrate => "migrate",
        }
    }
}

struct ObservedRepository<T: ?Sized> {
    inner: Arc<T>,
    backend: &'static str,
    metrics: crate::metrics::SharedMetrics,
}

impl<T: ?Sized> ObservedRepository<T> {
    fn new(inner: Arc<T>, backend: &'static str, metrics: crate::metrics::SharedMetrics) -> Self {
        Self {
            inner,
            backend,
            metrics,
        }
    }

    fn observe<R>(&self, operation: RepositoryOperation, result: Result<R>) -> Result<R> {
        if result.is_err() {
            self.metrics
                .repository_errors_total
                .with_label_values(&[self.backend, operation.as_str()])
                .inc();
        }
        result
    }
}

#[async_trait]
impl IntentRepository for ObservedRepository<dyn IntentRepository> {
    async fn create(&self, intent: CertificateIntent) -> Result<CreateOutcome> {
        let result = self.inner.create(intent).await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn get(
        &self,
        id: &crate::domain::IntentId,
    ) -> Result<Option<Versioned<CertificateIntent>>> {
        let result = self.inner.get(id).await;
        self.observe(RepositoryOperation::Read, result)
    }

    async fn update(
        &self,
        expected_revision: Revision,
        intent: CertificateIntent,
    ) -> Result<CasOutcome> {
        let result = self.inner.update(expected_revision, intent).await;
        self.observe(RepositoryOperation::Cas, result)
    }

    async fn list(&self) -> Result<Vec<Versioned<CertificateIntent>>> {
        let result = self.inner.list().await;
        self.observe(RepositoryOperation::Scan, result)
    }
}

#[async_trait]
impl LineageRepository for ObservedRepository<dyn LineageRepository> {
    async fn create(&self, lineage: CertificateLineage) -> Result<CreateOutcome> {
        let result = self.inner.create(lineage).await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn get(
        &self,
        id: &crate::domain::LineageId,
    ) -> Result<Option<Versioned<CertificateLineage>>> {
        let result = self.inner.get(id).await;
        self.observe(RepositoryOperation::Read, result)
    }

    async fn update(
        &self,
        expected_revision: Revision,
        lineage: CertificateLineage,
    ) -> Result<CasOutcome> {
        let result = self.inner.update(expected_revision, lineage).await;
        self.observe(RepositoryOperation::Cas, result)
    }

    async fn list(&self) -> Result<Vec<Versioned<CertificateLineage>>> {
        let result = self.inner.list().await;
        self.observe(RepositoryOperation::Scan, result)
    }
}

#[async_trait]
impl VersionRepository for ObservedRepository<dyn VersionRepository> {
    async fn create(&self, version: CertificateVersion) -> Result<CreateOutcome> {
        let result = self.inner.create(version).await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn get(
        &self,
        id: &crate::domain::VersionId,
    ) -> Result<Option<Versioned<CertificateVersion>>> {
        let result = self.inner.get(id).await;
        self.observe(RepositoryOperation::Read, result)
    }

    async fn update(
        &self,
        expected_revision: Revision,
        version: CertificateVersion,
    ) -> Result<CasOutcome> {
        let result = self.inner.update(expected_revision, version).await;
        self.observe(RepositoryOperation::Cas, result)
    }

    async fn list_by_lineage(
        &self,
        lineage_id: &crate::domain::LineageId,
    ) -> Result<Vec<Versioned<CertificateVersion>>> {
        let result = self.inner.list_by_lineage(lineage_id).await;
        self.observe(RepositoryOperation::Scan, result)
    }
}

#[async_trait]
impl OperationRepository for ObservedRepository<dyn OperationRepository> {
    async fn create(&self, operation: OperationRecord) -> Result<CreateOutcome> {
        let result = self.inner.create(operation).await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn get(&self, id: &OperationId) -> Result<Option<Versioned<OperationRecord>>> {
        let result = self.inner.get(id).await;
        self.observe(RepositoryOperation::Read, result)
    }

    async fn update(
        &self,
        expected_revision: Revision,
        operation: OperationRecord,
    ) -> Result<CasOutcome> {
        let result = self.inner.update(expected_revision, operation).await;
        self.observe(RepositoryOperation::Cas, result)
    }

    async fn list_ready(
        &self,
        now: Timestamp,
        limit: usize,
    ) -> Result<Vec<Versioned<OperationRecord>>> {
        let result = self.inner.list_ready(now, limit).await;
        self.observe(RepositoryOperation::Scan, result)
    }

    async fn list_by_status(
        &self,
        status: OperationStatus,
        limit: usize,
    ) -> Result<Vec<Versioned<OperationRecord>>> {
        let result = self.inner.list_by_status(status, limit).await;
        self.observe(RepositoryOperation::Scan, result)
    }

    async fn find_by_idempotency(
        &self,
        idempotency_key: &str,
        request_hash: &str,
    ) -> Result<Option<Versioned<OperationRecord>>> {
        let result = self
            .inner
            .find_by_idempotency(idempotency_key, request_hash)
            .await;
        self.observe(RepositoryOperation::Read, result)
    }

    async fn find_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<Versioned<OperationRecord>>> {
        let result = self.inner.find_by_idempotency_key(idempotency_key).await;
        self.observe(RepositoryOperation::Read, result)
    }
}

#[async_trait]
impl ChallengeLeaseRepository for ObservedRepository<dyn ChallengeLeaseRepository> {
    async fn create(&self, lease: ChallengeLease) -> Result<CreateOutcome> {
        let result = self.inner.create(lease).await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn get(
        &self,
        id: &crate::domain::ChallengeLeaseId,
    ) -> Result<Option<Versioned<ChallengeLease>>> {
        let result = self.inner.get(id).await;
        self.observe(RepositoryOperation::Read, result)
    }

    async fn update(
        &self,
        expected_revision: Revision,
        lease: ChallengeLease,
    ) -> Result<CasOutcome> {
        let result = self.inner.update(expected_revision, lease).await;
        self.observe(RepositoryOperation::Cas, result)
    }

    async fn list_needing_cleanup(&self) -> Result<Vec<Versioned<ChallengeLease>>> {
        let result = self.inner.list_needing_cleanup().await;
        self.observe(RepositoryOperation::Scan, result)
    }
}

#[async_trait]
impl ChallengeSessionRepository for ObservedRepository<dyn ChallengeSessionRepository> {
    async fn create(&self, session: crate::challenge::ChallengeSession) -> Result<CreateOutcome> {
        let result = self.inner.create(session).await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn get(&self, id: &str) -> Result<Option<Versioned<crate::challenge::ChallengeSession>>> {
        let result = self.inner.get(id).await;
        self.observe(RepositoryOperation::Read, result)
    }

    async fn update(
        &self,
        expected_revision: Revision,
        session: crate::challenge::ChallengeSession,
    ) -> Result<CasOutcome> {
        let result = self.inner.update(expected_revision, session).await;
        self.observe(RepositoryOperation::Cas, result)
    }

    async fn list_by_operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Vec<Versioned<crate::challenge::ChallengeSession>>> {
        let result = self.inner.list_by_operation(operation_id).await;
        self.observe(RepositoryOperation::Scan, result)
    }
}

#[async_trait]
impl DeploymentRepository for ObservedRepository<dyn DeploymentRepository> {
    async fn create(&self, deployment: DeploymentRecord) -> Result<CreateOutcome> {
        let result = self.inner.create(deployment).await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn get(
        &self,
        id: &crate::domain::DeploymentId,
    ) -> Result<Option<Versioned<DeploymentRecord>>> {
        let result = self.inner.get(id).await;
        self.observe(RepositoryOperation::Read, result)
    }

    async fn update(
        &self,
        expected_revision: Revision,
        deployment: DeploymentRecord,
    ) -> Result<CasOutcome> {
        let result = self.inner.update(expected_revision, deployment).await;
        self.observe(RepositoryOperation::Cas, result)
    }

    async fn list_by_version(
        &self,
        version_id: &crate::domain::VersionId,
    ) -> Result<Vec<Versioned<DeploymentRecord>>> {
        let result = self.inner.list_by_version(version_id).await;
        self.observe(RepositoryOperation::Scan, result)
    }

    async fn list_by_lineage(
        &self,
        lineage_id: &crate::domain::LineageId,
    ) -> Result<Vec<Versioned<DeploymentRecord>>> {
        let result = self.inner.list_by_lineage(lineage_id).await;
        self.observe(RepositoryOperation::Scan, result)
    }
}

#[async_trait]
impl AccountRepository for ObservedRepository<dyn AccountRepository> {
    async fn upsert(&self, account: AccountRecord) -> Result<()> {
        let result = self.inner.upsert(account).await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn get(&self, id: &str) -> Result<Option<Versioned<AccountRecord>>> {
        let result = self.inner.get(id).await;
        self.observe(RepositoryOperation::Read, result)
    }

    async fn list(&self) -> Result<Vec<Versioned<AccountRecord>>> {
        let result = self.inner.list().await;
        self.observe(RepositoryOperation::Scan, result)
    }
}

#[async_trait]
impl OutboxRepository for ObservedRepository<dyn OutboxRepository> {
    async fn append(
        &self,
        event_type: &str,
        payload: Value,
        event_id: Option<String>,
    ) -> Result<u64> {
        let result = self.inner.append(event_type, payload, event_id).await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn list_pending(&self, limit: usize) -> Result<Vec<OutboxEvent>> {
        let result = self.inner.list_pending(limit).await;
        self.observe(RepositoryOperation::Scan, result)
    }

    async fn mark_processed(&self, sequence: u64) -> Result<()> {
        let result = self.inner.mark_processed(sequence).await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn mark_failed(
        &self,
        sequence: u64,
        error: &str,
        next_attempt_at: Option<Timestamp>,
    ) -> Result<()> {
        let result = self
            .inner
            .mark_failed(sequence, error, next_attempt_at)
            .await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn dead_letter(&self, sequence: u64, reason: &str) -> Result<()> {
        let result = self.inner.dead_letter(sequence, reason).await;
        self.observe(RepositoryOperation::Write, result)
    }

    async fn requeue(&self, sequence: u64) -> Result<()> {
        let result = self.inner.requeue(sequence).await;
        self.observe(RepositoryOperation::Write, result)
    }
}

#[async_trait]
impl LeaseManager for ObservedRepository<dyn LeaseManager> {
    async fn acquire(&self, key: &str, owner: &str, ttl: Duration) -> Result<LeaseOutcome> {
        let result = self.inner.acquire(key, owner, ttl).await;
        self.observe(RepositoryOperation::Cas, result)
    }

    async fn renew(
        &self,
        key: &str,
        owner: &str,
        fencing_token: FencingToken,
        ttl: Duration,
    ) -> Result<Option<LeaseGrant>> {
        let result = self.inner.renew(key, owner, fencing_token, ttl).await;
        self.observe(RepositoryOperation::Cas, result)
    }

    async fn release(&self, key: &str, owner: &str, fencing_token: FencingToken) -> Result<()> {
        let result = self.inner.release(key, owner, fencing_token).await;
        self.observe(RepositoryOperation::Cas, result)
    }
}

#[async_trait]
impl MigrationManifestStore for ObservedRepository<dyn MigrationManifestStore> {
    async fn save_entry(&self, entry: MigrationManifestEntry) -> Result<()> {
        let result = self.inner.save_entry(entry).await;
        self.observe(RepositoryOperation::Migrate, result)
    }

    async fn entries(&self) -> Result<Vec<MigrationManifestEntry>> {
        let result = self.inner.entries().await;
        self.observe(RepositoryOperation::Migrate, result)
    }
}

// ---------------------------------------------------------------------------
// Internal generic envelope machinery shared by the Memory and File
// backends. Envelopes are stored as JSON values with metadata.
// ---------------------------------------------------------------------------

pub(crate) const SCHEMA_VERSION: u32 = 1;
pub(crate) const ENVELOPE_REVISION_FIELD: &str = "revision";

pub(crate) struct Envelope {
    pub id: String,
    pub value: Value,
}

pub(crate) fn envelope_revision(value: &Value) -> Result<Revision> {
    value
        .get(ENVELOPE_REVISION_FIELD)
        .and_then(Value::as_u64)
        .ok_or_else(|| corrupt("missing revision"))
}

pub(crate) fn corrupt(detail: impl std::fmt::Display) -> AcmeError {
    AcmeError::Storage(format!("corrupt entity data: {detail}"))
}

/// Internal per-aggregate store both backends implement.
#[async_trait]
pub(crate) trait EntityStore: Send + Sync {
    async fn env_get(&self, aggregate: &str, id: &str) -> Result<Option<Value>>;
    async fn env_create(
        &self,
        aggregate: &str,
        id: &str,
        data: &Value,
        now: Timestamp,
    ) -> Result<CreateOutcome>;
    async fn env_cas(
        &self,
        aggregate: &str,
        id: &str,
        expected: Revision,
        data: &Value,
        now: Timestamp,
    ) -> Result<CasOutcome>;
    async fn env_list(&self, aggregate: &str) -> Result<Vec<Envelope>>;
    #[allow(dead_code)] // archive/delete flows arrive with the application service (T08)
    async fn env_delete(&self, aggregate: &str, id: &str) -> Result<()>;
}

/// Generic aggregate-repository implementation over any [`EntityStore`].
pub(crate) struct GenericRepository<S> {
    store: S,
    clock: Arc<dyn Clock>,
}

impl<S: EntityStore + 'static> GenericRepository<S> {
    pub(crate) fn new(store: S, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock }
    }

    pub(crate) async fn get_as<T: serde::de::DeserializeOwned>(
        &self,
        aggregate: &str,
        id: &str,
    ) -> Result<Option<Versioned<T>>> {
        let Some(value) = self.store.env_get(aggregate, id).await? else {
            return Ok(None);
        };
        Ok(Some(decode_versioned(&value).map_err(|e| {
            AcmeError::Storage(format!("corrupt {aggregate} `{id}`: {e}"))
        })?))
    }

    pub(crate) async fn create_as<T: Serialize>(
        &self,
        aggregate: &str,
        id: &str,
        entity: &T,
    ) -> Result<CreateOutcome> {
        let data = serde_json::to_value(entity)?;
        self.store
            .env_create(aggregate, id, &data, self.clock.now())
            .await
    }

    pub(crate) async fn cas_as<T: Serialize>(
        &self,
        aggregate: &str,
        id: &str,
        expected: Revision,
        entity: &T,
    ) -> Result<CasOutcome> {
        let data = serde_json::to_value(entity)?;
        self.store
            .env_cas(aggregate, id, expected, &data, self.clock.now())
            .await
    }

    pub(crate) async fn list_as<T: serde::de::DeserializeOwned>(
        &self,
        aggregate: &str,
    ) -> Result<Vec<Versioned<T>>> {
        let mut out = Vec::new();
        for envelope in self.store.env_list(aggregate).await? {
            match decode_versioned::<T>(&envelope.value) {
                Ok(v) => out.push(v),
                Err(err) => {
                    return Err(AcmeError::Storage(format!(
                        "corrupt {aggregate} `{}`: {err}",
                        envelope.id
                    )));
                }
            }
        }
        Ok(out)
    }
}

pub(crate) fn decode_versioned<T: serde::de::DeserializeOwned>(
    value: &Value,
) -> std::result::Result<Versioned<T>, String> {
    let revision = value
        .get(ENVELOPE_REVISION_FIELD)
        .and_then(Value::as_u64)
        .ok_or("missing revision")?;
    let schema_version = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or("missing schema_version")? as u32;
    let created_at = value
        .get("created_at")
        .and_then(Value::as_str)
        .ok_or("missing created_at")?;
    let updated_at = value
        .get("updated_at")
        .and_then(Value::as_str)
        .ok_or("missing updated_at")?;
    let data = value.get("data").ok_or("missing data")?;
    Ok(Versioned {
        value: serde_json::from_value(data.clone()).map_err(|e| e.to_string())?,
        revision,
        schema_version,
        created_at: Timestamp::from_str(created_at).map_err(|e| e.to_string())?,
        updated_at: Timestamp::from_str(updated_at).map_err(|e| e.to_string())?,
    })
}

// ---------------------------------------------------------------------------
// Aggregate trait implementations over GenericRepository. All backends get
// these for free; only the EntityStore differs.
// ---------------------------------------------------------------------------

#[async_trait]
impl<S: EntityStore + 'static> IntentRepository for GenericRepository<S> {
    async fn create(&self, intent: CertificateIntent) -> Result<CreateOutcome> {
        self.create_as("intents", intent.id.as_str(), &intent).await
    }

    async fn get(
        &self,
        id: &crate::domain::IntentId,
    ) -> Result<Option<Versioned<CertificateIntent>>> {
        self.get_as("intents", id.as_str()).await
    }

    async fn update(
        &self,
        expected_revision: Revision,
        intent: CertificateIntent,
    ) -> Result<CasOutcome> {
        self.cas_as("intents", intent.id.as_str(), expected_revision, &intent)
            .await
    }

    async fn list(&self) -> Result<Vec<Versioned<CertificateIntent>>> {
        self.list_as("intents").await
    }
}

#[async_trait]
impl<S: EntityStore + 'static> LineageRepository for GenericRepository<S> {
    async fn create(&self, lineage: CertificateLineage) -> Result<CreateOutcome> {
        self.create_as("lineages", lineage.id.as_str(), &lineage)
            .await
    }

    async fn get(
        &self,
        id: &crate::domain::LineageId,
    ) -> Result<Option<Versioned<CertificateLineage>>> {
        self.get_as("lineages", id.as_str()).await
    }

    async fn update(
        &self,
        expected_revision: Revision,
        lineage: CertificateLineage,
    ) -> Result<CasOutcome> {
        self.cas_as("lineages", lineage.id.as_str(), expected_revision, &lineage)
            .await
    }

    async fn list(&self) -> Result<Vec<Versioned<CertificateLineage>>> {
        self.list_as("lineages").await
    }
}

#[async_trait]
impl<S: EntityStore + 'static> VersionRepository for GenericRepository<S> {
    async fn create(&self, version: CertificateVersion) -> Result<CreateOutcome> {
        self.create_as("versions", version.id.as_str(), &version)
            .await
    }

    async fn get(
        &self,
        id: &crate::domain::VersionId,
    ) -> Result<Option<Versioned<CertificateVersion>>> {
        self.get_as("versions", id.as_str()).await
    }

    async fn update(
        &self,
        expected_revision: Revision,
        version: CertificateVersion,
    ) -> Result<CasOutcome> {
        self.cas_as("versions", version.id.as_str(), expected_revision, &version)
            .await
    }

    async fn list_by_lineage(
        &self,
        lineage_id: &crate::domain::LineageId,
    ) -> Result<Vec<Versioned<CertificateVersion>>> {
        let mut all = self.list_as::<CertificateVersion>("versions").await?;
        all.retain(|v| v.value.lineage_id == *lineage_id);
        Ok(all)
    }
}

#[async_trait]
impl<S: EntityStore + 'static> OperationRepository for GenericRepository<S> {
    async fn create(&self, operation: OperationRecord) -> Result<CreateOutcome> {
        self.create_as("operations", operation.id.as_str(), &operation)
            .await
    }

    async fn get(&self, id: &OperationId) -> Result<Option<Versioned<OperationRecord>>> {
        self.get_as("operations", id.as_str()).await
    }

    async fn update(
        &self,
        expected_revision: Revision,
        operation: OperationRecord,
    ) -> Result<CasOutcome> {
        self.cas_as(
            "operations",
            operation.id.as_str(),
            expected_revision,
            &operation,
        )
        .await
    }

    async fn list_ready(
        &self,
        now: Timestamp,
        limit: usize,
    ) -> Result<Vec<Versioned<OperationRecord>>> {
        let mut all = self.list_as::<OperationRecord>("operations").await?;
        all.retain(|v| v.value.is_ready_at(now));
        all.sort_by_key(|a| a.value.created_at);
        all.truncate(limit);
        Ok(all)
    }

    async fn list_by_status(
        &self,
        status: OperationStatus,
        limit: usize,
    ) -> Result<Vec<Versioned<OperationRecord>>> {
        let mut all = self.list_as::<OperationRecord>("operations").await?;
        all.retain(|v| v.value.status == status);
        all.sort_by_key(|a| a.value.created_at);
        all.truncate(limit);
        Ok(all)
    }

    async fn find_by_idempotency(
        &self,
        idempotency_key: &str,
        request_hash: &str,
    ) -> Result<Option<Versioned<OperationRecord>>> {
        let all = self.list_as::<OperationRecord>("operations").await?;
        Ok(all.into_iter().find(|v| {
            v.value.idempotency_key.as_deref() == Some(idempotency_key)
                && v.value.request_hash.as_deref() == Some(request_hash)
        }))
    }

    async fn find_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<Versioned<OperationRecord>>> {
        let all = self.list_as::<OperationRecord>("operations").await?;
        Ok(all
            .into_iter()
            .find(|v| v.value.idempotency_key.as_deref() == Some(idempotency_key)))
    }
}

#[async_trait]
impl<S: EntityStore + 'static> ChallengeLeaseRepository for GenericRepository<S> {
    async fn create(&self, lease: ChallengeLease) -> Result<CreateOutcome> {
        self.create_as("challenge-leases", lease.id.as_str(), &lease)
            .await
    }

    async fn get(
        &self,
        id: &crate::domain::ChallengeLeaseId,
    ) -> Result<Option<Versioned<ChallengeLease>>> {
        self.get_as("challenge-leases", id.as_str()).await
    }

    async fn update(
        &self,
        expected_revision: Revision,
        lease: ChallengeLease,
    ) -> Result<CasOutcome> {
        self.cas_as(
            "challenge-leases",
            lease.id.as_str(),
            expected_revision,
            &lease,
        )
        .await
    }

    async fn list_needing_cleanup(&self) -> Result<Vec<Versioned<ChallengeLease>>> {
        let mut all = self.list_as::<ChallengeLease>("challenge-leases").await?;
        all.retain(|v| v.value.needs_cleanup());
        Ok(all)
    }
}

#[async_trait]
impl<S: EntityStore + 'static> ChallengeSessionRepository for GenericRepository<S> {
    async fn create(&self, session: crate::challenge::ChallengeSession) -> Result<CreateOutcome> {
        self.create_as("challenge-sessions", &session.id, &session)
            .await
    }

    async fn get(&self, id: &str) -> Result<Option<Versioned<crate::challenge::ChallengeSession>>> {
        self.get_as("challenge-sessions", id).await
    }

    async fn update(
        &self,
        expected_revision: Revision,
        session: crate::challenge::ChallengeSession,
    ) -> Result<CasOutcome> {
        self.cas_as(
            "challenge-sessions",
            &session.id,
            expected_revision,
            &session,
        )
        .await
    }

    async fn list_by_operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Vec<Versioned<crate::challenge::ChallengeSession>>> {
        let mut all = self
            .list_as::<crate::challenge::ChallengeSession>("challenge-sessions")
            .await?;
        all.retain(|s| s.value.operation_id == *operation_id);
        Ok(all)
    }
}

#[async_trait]
impl<S: EntityStore + 'static> DeploymentRepository for GenericRepository<S> {
    async fn create(&self, deployment: DeploymentRecord) -> Result<CreateOutcome> {
        self.create_as("deployments", deployment.id.as_str(), &deployment)
            .await
    }

    async fn get(
        &self,
        id: &crate::domain::DeploymentId,
    ) -> Result<Option<Versioned<DeploymentRecord>>> {
        self.get_as("deployments", id.as_str()).await
    }

    async fn update(
        &self,
        expected_revision: Revision,
        deployment: DeploymentRecord,
    ) -> Result<CasOutcome> {
        self.cas_as(
            "deployments",
            deployment.id.as_str(),
            expected_revision,
            &deployment,
        )
        .await
    }

    async fn list_by_version(
        &self,
        version_id: &crate::domain::VersionId,
    ) -> Result<Vec<Versioned<DeploymentRecord>>> {
        let mut all = self.list_as::<DeploymentRecord>("deployments").await?;
        all.retain(|v| v.value.version_id == *version_id);
        Ok(all)
    }

    async fn list_by_lineage(
        &self,
        lineage_id: &crate::domain::LineageId,
    ) -> Result<Vec<Versioned<DeploymentRecord>>> {
        let mut all = self.list_as::<DeploymentRecord>("deployments").await?;
        all.retain(|v| v.value.lineage_id == *lineage_id);
        Ok(all)
    }
}

/// Builds the envelope JSON for a new entity.
pub(crate) fn make_envelope(data: &Value, now: Timestamp) -> Value {
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "revision": 1u64,
        "created_at": now.to_string(),
        "updated_at": now.to_string(),
        "data": data,
    })
}

/// Rebuilds the envelope with a bumped revision and timestamp.
pub(crate) fn bump_envelope(previous: &Value, data: &Value, now: Timestamp) -> Result<Value> {
    let revision = envelope_revision(previous)? + 1;
    let created_at = previous
        .get("created_at")
        .and_then(Value::as_str)
        .ok_or_else(|| corrupt("missing created_at"))?;
    Ok(serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "revision": revision,
        "created_at": created_at,
        "updated_at": now.to_string(),
        "data": data,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_operation_labels_are_closed_and_stable() {
        assert_eq!(RepositoryOperation::Read.as_str(), "read");
        assert_eq!(RepositoryOperation::Write.as_str(), "write");
        assert_eq!(RepositoryOperation::Scan.as_str(), "scan");
        assert_eq!(RepositoryOperation::Cas.as_str(), "cas");
        assert_eq!(RepositoryOperation::Migrate.as_str(), "migrate");
        for operation in ["read", "write", "scan", "cas", "migrate"] {
            assert!(crate::metrics::validate_metric_label(
                "operation",
                operation
            ));
        }
    }

    #[test]
    fn repository_sets_declare_their_backend() {
        let memory = MemoryRepository::new().into_set();
        assert_eq!(memory.backend, "memory");
        assert!(crate::metrics::validate_metric_label(
            "backend",
            memory.backend
        ));
    }
}
