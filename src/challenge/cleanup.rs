//! Orphaned-lease cleanup: rescues resources whose operation already
//! reached a terminal state (crash, cancel, compensation failure).
//!
//! The owning operation's compensation normally cleans its leases; the
//! scanner is the safety net that runs periodically (or on startup) and
//! retries until every lease is `Cleaned` or explicitly alerting.

use crate::domain::challenge::{ChallengeLease, ChallengeLeaseState};
use crate::error::Result;
use crate::repository::RepositorySet;

use super::presenter::{CleanupOutcome, PresenterRegistry};

/// Scans leases needing cleanup and drives them to `Cleaned`.
pub struct ChallengeCleanupScanner {
    presenters: PresenterRegistry,
    repositories: RepositorySet,
    max_cleanup_attempts: u32,
}

/// One lease's cleanup outcome in a scan pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    /// Lease cleaned in this pass.
    Cleaned,
    /// Lease already gone.
    AlreadyAbsent,
    /// Cleanup failed again; retry remains scheduled.
    RetryScheduled,
    /// Cleanup failed beyond the budget; marked `cleanup_failed` for alerting.
    MarkedFailed,
    /// No presenter registered for the lease's challenge type.
    NoPresenter,
}

impl ChallengeCleanupScanner {
    /// Creates a scanner.
    pub fn new(presenters: PresenterRegistry, repositories: RepositorySet) -> Self {
        Self {
            presenters,
            repositories,
            max_cleanup_attempts: 5,
        }
    }

    /// Runs one scan pass over all leases needing cleanup.
    pub async fn scan_once(&self) -> Result<Vec<(String, ScanOutcome)>> {
        let mut results = Vec::new();
        for lease in self
            .repositories
            .challenge_leases
            .list_needing_cleanup()
            .await?
        {
            let outcome = self.cleanup_lease(&lease.value).await?;
            results.push((lease.value.id.to_string(), outcome));
        }
        Ok(results)
    }

    /// Cleans a single lease, updating its persisted state.
    pub async fn cleanup_lease(&self, lease: &ChallengeLease) -> Result<ScanOutcome> {
        let Some(presenter) = self.presenters.get(lease.challenge_type) else {
            return Ok(ScanOutcome::NoPresenter);
        };

        let attempts = lease.cleanup_attempts + 1;
        match presenter.cleanup(lease).await {
            Ok(outcome) => {
                let now = self.repositories.clock.now();
                let mut updated = lease.clone();
                updated.cleanup_attempts = attempts;
                updated.state = ChallengeLeaseState::Cleaned;
                updated.cleaned_at = Some(now);
                updated.last_cleanup_error = None;
                self.persist(lease, updated).await?;
                Ok(match outcome {
                    CleanupOutcome::Cleaned => ScanOutcome::Cleaned,
                    CleanupOutcome::AlreadyAbsent => ScanOutcome::AlreadyAbsent,
                })
            }
            Err(err) => {
                let mut updated = lease.clone();
                updated.cleanup_attempts = attempts;
                updated.last_cleanup_error = Some(err.to_string());
                if attempts >= self.max_cleanup_attempts {
                    updated.state = ChallengeLeaseState::CleanupFailed;
                    tracing::error!(
                        lease = lease.id.to_string(),
                        attempts,
                        "challenge cleanup exhausted; operator action required"
                    );
                    self.persist(lease, updated).await?;
                    Ok(ScanOutcome::MarkedFailed)
                } else {
                    // Stay pending: the next scan pass retries.
                    updated.state = ChallengeLeaseState::CleanupPending;
                    self.persist(lease, updated).await?;
                    Ok(ScanOutcome::RetryScheduled)
                }
            }
        }
    }

    async fn persist(&self, previous: &ChallengeLease, updated: ChallengeLease) -> Result<()> {
        // Re-read for the current revision; best-effort CAS loop.
        loop {
            let Some(stored) = self.repositories.challenge_leases.get(&previous.id).await? else {
                return Ok(());
            };
            match self
                .repositories
                .challenge_leases
                .update(stored.revision, updated.clone())
                .await?
            {
                crate::repository::CasOutcome::Updated(_) => return Ok(()),
                crate::repository::CasOutcome::Conflict { .. } => continue,
            }
        }
    }
}
