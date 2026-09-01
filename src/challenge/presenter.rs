//! The challenge presenter port: prepare / observe / cleanup external
//! validation resources.
//!
//! Presenters are **stateless services** — all per-challenge state lives in
//! the persisted [`ChallengeSession`] and [`ChallengeLease`]. `prepare`
//! returns a serializable lease; `observe` only reads external state;
//! `cleanup` is idempotent (`AlreadyAbsent` counts as success).
//!
//! Concrete adapters: DNS-01 (T06), HTTP-01/TLS-ALPN-01 (T07). This module
//! ships the port, an in-memory presenter for tests, and a compatibility
//! adapter wrapping the legacy mutable solvers.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::domain::challenge::{ChallengeLease, ChallengeLeaseLocator};
use crate::error::Result;
use crate::types::ChallengeType;

use super::session::ChallengeSession;

/// Input to `prepare`.
pub struct PrepareChallenge {
    /// The session being prepared.
    pub session: ChallengeSession,
    /// The key authorization (token.fingerprint) — passed by reference,
    /// never persisted by presenters.
    pub key_authorization: String,
}

/// Result of observing an external resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// The expected content is externally visible.
    Propagated,
    /// Not visible yet; re-check after the suggested delay.
    NotYet {
        /// Suggested re-observation delay.
        retry_after: std::time::Duration,
    },
}

/// Result of an idempotent cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupOutcome {
    /// The resource was removed by this call.
    Cleaned,
    /// The resource was already gone.
    AlreadyAbsent,
}

impl CleanupOutcome {
    /// Both variants mean the cleanup goal is met.
    pub fn is_clean(self) -> bool {
        matches!(self, Self::Cleaned | Self::AlreadyAbsent)
    }
}

/// Creates, observes and removes one kind of external challenge resource.
#[async_trait]
pub trait ChallengePresenter: Send + Sync {
    /// Which challenge family this presenter handles.
    fn kind(&self) -> ChallengeType;

    /// Creates the external resource and returns its lease. Must be
    /// idempotent per session id (a retry after a crash must find or
    /// re-create the same resource, not duplicate it).
    async fn prepare(&self, request: PrepareChallenge) -> Result<ChallengeLease>;

    /// Observes external visibility without modifying anything.
    async fn observe(&self, lease: &ChallengeLease) -> Result<Observation>;

    /// Removes exactly the resource described by the lease. Idempotent.
    async fn cleanup(&self, lease: &ChallengeLease) -> Result<CleanupOutcome>;
}

/// Immutable registry of presenters by challenge type.
///
/// Unlike the legacy solver registry, presenters carry no per-challenge
/// mutable state, so any number of sessions can run concurrently.
#[derive(Clone, Default)]
pub struct PresenterRegistry {
    presenters: HashMap<ChallengeType, Arc<dyn ChallengePresenter>>,
}

impl PresenterRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a presenter.
    pub fn register(&mut self, presenter: Arc<dyn ChallengePresenter>) {
        self.presenters.insert(presenter.kind(), presenter);
    }

    /// Looks up the presenter for a challenge type.
    pub fn get(&self, kind: ChallengeType) -> Option<Arc<dyn ChallengePresenter>> {
        self.presenters.get(&kind).cloned()
    }

    /// Which challenge types have presenters.
    pub fn kinds(&self) -> Vec<ChallengeType> {
        self.presenters.keys().copied().collect()
    }
}

/// An in-memory presenter for tests and examples.
///
/// Tracks "resources" by record name with value hashes, mirroring the
/// multi-value semantics DNS TXT records have: same-name resources from
/// different sessions coexist and cleanup removes only this lease's value.
pub struct MemoryPresenter {
    kind: ChallengeType,
    resources: tokio::sync::Mutex<HashMap<(String, String), String>>, // (name, value_hash) -> value
    behavior: MemoryPresenterBehavior,
    prepare_attempts: std::sync::atomic::AtomicUsize,
    observe_attempts: std::sync::atomic::AtomicUsize,
    cleanup_attempts: std::sync::atomic::AtomicUsize,
}

/// Scriptable behavior knobs for [`MemoryPresenter`].
#[derive(Debug, Clone, Default)]
pub struct MemoryPresenterBehavior {
    /// Cleanup fails this many times before succeeding (simulates provider
    /// 5xx during cleanup retries).
    pub cleanup_failures_first: usize,
    /// Observation returns NotYet this many times before Propagated.
    pub observe_not_yet_first: usize,
    /// Prepare fails this many times before succeeding.
    pub prepare_failures_first: usize,
}

impl MemoryPresenter {
    /// A DNS-01-flavored memory presenter with default (successful)
    /// behavior.
    pub fn dns01(behavior: MemoryPresenterBehavior) -> Arc<Self> {
        Arc::new(Self::build(ChallengeType::Dns01, behavior))
    }

    /// An HTTP-01-flavored memory presenter.
    pub fn http01(behavior: MemoryPresenterBehavior) -> Arc<Self> {
        Arc::new(Self::build(ChallengeType::Http01, behavior))
    }

    fn build(kind: ChallengeType, behavior: MemoryPresenterBehavior) -> Self {
        Self {
            kind,
            resources: tokio::sync::Mutex::new(HashMap::new()),
            behavior,
            prepare_attempts: std::sync::atomic::AtomicUsize::new(0),
            observe_attempts: std::sync::atomic::AtomicUsize::new(0),
            cleanup_attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// How many resources currently exist.
    pub async fn resource_count(&self) -> usize {
        self.resources.lock().await.len()
    }

    /// Whether a specific (name, value) resource exists.
    pub async fn has_resource(&self, name: &str, value_hash: &str) -> bool {
        self.resources
            .lock()
            .await
            .contains_key(&(name.to_string(), value_hash.to_string()))
    }
}

#[async_trait]
impl ChallengePresenter for MemoryPresenter {
    fn kind(&self) -> ChallengeType {
        self.kind
    }

    async fn prepare(&self, request: PrepareChallenge) -> Result<ChallengeLease> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(request.key_authorization.as_bytes());
        let value_hash = hex::encode(hasher.finalize());

        {
            // Scripted transient failures: the caller retries and the
            // resource is created on the successful attempt (idempotency).
            if self
                .prepare_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                < self.behavior.prepare_failures_first
            {
                return Err(crate::error::AcmeError::protocol(
                    "scripted prepare failure".to_string(),
                ));
            }
            let mut resources = self.resources.lock().await;
            resources.insert(
                (
                    format!("_acme-challenge.{}", request.session.identifier),
                    value_hash.clone(),
                ),
                request.key_authorization.clone(),
            );
        }

        let now = jiff::Timestamp::now();
        Ok(ChallengeLease {
            id: crate::domain::ChallengeLeaseId::generate(),
            operation_id: request.session.operation_id.clone(),
            identifier: request.session.identifier.clone(),
            challenge_type: self.kind,
            locator: ChallengeLeaseLocator::Dns {
                provider_id: "memory".to_string(),
                zone: "example.com".to_string(),
                record_name: format!("_acme-challenge.{}", request.session.identifier),
                record_id: None,
                value_hash,
            },
            created_at: now,
            expires_at: now
                .checked_add(jiff::Span::new().minutes(30))
                .unwrap_or(now),
            state: crate::domain::ChallengeLeaseState::Active,
            cleanup_attempts: 0,
            last_cleanup_error: None,
            cleaned_at: None,
        })
    }

    async fn observe(&self, lease: &ChallengeLease) -> Result<Observation> {
        if self
            .observe_attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            < self.behavior.observe_not_yet_first
        {
            return Ok(Observation::NotYet {
                retry_after: std::time::Duration::from_millis(10),
            });
        }
        let resources = self.resources.lock().await;
        let exists = match &lease.locator {
            ChallengeLeaseLocator::Dns {
                record_name,
                value_hash,
                ..
            } => resources.contains_key(&(record_name.clone(), value_hash.clone())),
            ChallengeLeaseLocator::Http { token_hash, .. } => {
                resources.contains_key(&(lease.id.to_string(), token_hash.clone()))
            }
            ChallengeLeaseLocator::Tls { fingerprint, .. } => {
                resources.contains_key(&(lease.id.to_string(), fingerprint.clone()))
            }
        };
        if exists {
            Ok(Observation::Propagated)
        } else {
            Ok(Observation::NotYet {
                retry_after: std::time::Duration::from_millis(10),
            })
        }
    }

    async fn cleanup(&self, lease: &ChallengeLease) -> Result<CleanupOutcome> {
        if self
            .cleanup_attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            < self.behavior.cleanup_failures_first
        {
            return Err(crate::error::AcmeError::protocol(
                "scripted cleanup failure".to_string(),
            ));
        }
        let mut resources = self.resources.lock().await;
        let key = match &lease.locator {
            ChallengeLeaseLocator::Dns {
                record_name,
                value_hash,
                ..
            } => (record_name.clone(), value_hash.clone()),
            ChallengeLeaseLocator::Http { token_hash, .. } => {
                (lease.id.to_string(), token_hash.clone())
            }
            ChallengeLeaseLocator::Tls { fingerprint, .. } => {
                (lease.id.to_string(), fingerprint.clone())
            }
        };
        if resources.remove(&key).is_some() {
            Ok(CleanupOutcome::Cleaned)
        } else {
            Ok(CleanupOutcome::AlreadyAbsent)
        }
    }
}

/// Compatibility adapter wrapping one legacy mutable solver as a presenter.
///
/// Each `prepare` call constructs an isolated in-flight state keyed by
/// session; the adapter exists only to keep legacy tests and callers
/// working during migration (T06/T07 replace it with native presenters).
pub struct LegacySolverPresenter {
    kind: ChallengeType,
    #[allow(clippy::type_complexity)]
    factory: Box<dyn Fn() -> Box<dyn super::ChallengeSolver> + Send + Sync>,
}

impl LegacySolverPresenter {
    /// Wraps a solver factory; a fresh solver instance is created per
    /// session so mutable state never crosses challenge boundaries.
    pub fn new(
        kind: ChallengeType,
        factory: impl Fn() -> Box<dyn super::ChallengeSolver> + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            factory: Box::new(factory),
        }
    }
}

#[async_trait]
impl ChallengePresenter for LegacySolverPresenter {
    fn kind(&self) -> ChallengeType {
        self.kind
    }

    async fn prepare(&self, request: PrepareChallenge) -> Result<ChallengeLease> {
        let mut solver = (self.factory)();
        let challenge = crate::order::Challenge {
            challenge_type: self.kind.as_str().to_string(),
            url: request.session.challenge_url.clone(),
            status: "pending".to_string(),
            // Legacy solvers read the token from the challenge struct; the
            // session stores only its hash, so reconstruct from the key
            // authorization prefix (token.fingerprint).
            token: request
                .key_authorization
                .split('.')
                .next()
                .unwrap_or_default()
                .to_string(),
            key_authorization: None,
            validation: None,
            updated: None,
            error: None,
        };
        solver
            .prepare(
                &challenge,
                &request.session.identifier,
                &request.key_authorization,
            )
            .await?;
        solver.present().await?;

        let now = jiff::Timestamp::now();
        Ok(ChallengeLease {
            id: crate::domain::ChallengeLeaseId::generate(),
            operation_id: request.session.operation_id.clone(),
            identifier: request.session.identifier.clone(),
            challenge_type: self.kind,
            locator: ChallengeLeaseLocator::Http {
                agent_id: "legacy".to_string(),
                route_id: request.session.id.clone(),
                token_hash: request.session.token_hash.clone(),
                endpoint: request.session.challenge_url.clone(),
            },
            created_at: now,
            expires_at: now
                .checked_add(jiff::Span::new().minutes(30))
                .unwrap_or(now),
            state: crate::domain::ChallengeLeaseState::Active,
            cleanup_attempts: 0,
            last_cleanup_error: None,
            cleaned_at: None,
        })
    }

    async fn observe(&self, lease: &ChallengeLease) -> Result<Observation> {
        // Legacy solvers' verify() only checks in-memory state; treat the
        // lease's existence as "externally visible" for the adapter.
        let _ = lease;
        Ok(Observation::Propagated)
    }

    async fn cleanup(&self, _lease: &ChallengeLease) -> Result<CleanupOutcome> {
        let mut solver = (self.factory)();
        solver.cleanup().await?;
        Ok(CleanupOutcome::Cleaned)
    }
}
