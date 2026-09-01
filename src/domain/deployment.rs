//! Deployment model: delivering a certificate version to one target.
//!
//! Each delivery target gets its own [`DeploymentRecord`] progressing
//! through stage → activate → health, with rollback and cleanup paths. The
//! lineage's active version pointer is only switched once the intent's
//! delivery requirement (required/quorum/best-effort) is satisfied.

use serde::{Deserialize, Serialize};

use jiff::Timestamp;

use super::ids::{DeploymentId, LineageId, TargetId, VersionId};

/// Lifecycle state of a single-target deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentState {
    /// Not started.
    Pending,
    /// Writing the new version without touching the active pointer.
    Staging,
    /// Staged and ready to activate.
    Staged,
    /// Switching the target to the new version.
    Activating,
    /// New version live at the target.
    Active,
    /// Post-activation health check passed.
    Healthy,
    /// Deployment failed.
    Failed,
    /// Rolling back to the previous version.
    RollingBack,
    /// Rollback completed.
    RolledBack,
    /// Rollback failed; operator attention required.
    RollbackFailed,
    /// Old version artifacts pending removal.
    CleanupPending,
    /// Cleanup completed.
    Cleaned,
}

impl DeploymentState {
    /// Stable wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Staging => "staging",
            Self::Staged => "staged",
            Self::Activating => "activating",
            Self::Active => "active",
            Self::Healthy => "healthy",
            Self::Failed => "failed",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
            Self::RollbackFailed => "rollback_failed",
            Self::CleanupPending => "cleanup_pending",
            Self::Cleaned => "cleaned",
        }
    }

    /// Successful end states.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Healthy | Self::Active)
    }
}

/// Deployment progress for one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentRecord {
    /// Unique deployment identity.
    pub id: DeploymentId,
    /// The version being deployed.
    pub version_id: VersionId,
    /// The lineage the version belongs to.
    pub lineage_id: LineageId,
    /// Which delivery target this deployment writes to.
    pub target_id: TargetId,
    /// Current state.
    pub state: DeploymentState,
    /// Sink-specific staging reference (e.g. staged directory), used by
    /// activate/health/rollback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staged_ref: Option<String>,
    /// Attempt counter.
    #[serde(default)]
    pub attempts: u32,
    /// Last classified error, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Creation time.
    pub created_at: Timestamp,
    /// Last update time.
    pub updated_at: Timestamp,
}

impl DeploymentRecord {
    /// A fresh pending deployment.
    pub fn new(
        id: DeploymentId,
        version_id: VersionId,
        lineage_id: LineageId,
        target_id: TargetId,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            version_id,
            lineage_id,
            target_id,
            state: DeploymentState::Pending,
            staged_ref: None,
            attempts: 0,
            last_error: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Validates and applies a state transition.
    pub fn transition(&self, next: DeploymentState) -> Result<DeploymentRecord, String> {
        use DeploymentState as S;
        let legal = matches!(
            (self.state, next),
            (S::Pending, S::Staging)
                | (S::Pending, S::Failed)
                | (S::Staging, S::Staged)
                | (S::Staging, S::Failed)
                | (S::Staged, S::Activating)
                | (S::Staged, S::Failed)
                | (S::Activating, S::Active)
                | (S::Activating, S::Failed)
                | (S::Active, S::Healthy)
                | (S::Active, S::RollingBack)
                | (S::Healthy, S::RollingBack)
                | (S::Healthy, S::CleanupPending)
                | (S::Failed, S::Staging)
                | (S::Failed, S::RollingBack)
                | (S::RollingBack, S::RolledBack)
                | (S::RollingBack, S::RollbackFailed)
                | (S::RollbackFailed, S::RollingBack)
                | (S::CleanupPending, S::Cleaned)
                | (S::CleanupPending, S::Failed)
                | (S::Cleaned, S::Cleaned)
        );
        if !legal {
            return Err(format!(
                "illegal deployment transition {:?} -> {:?}",
                self.state, next
            ));
        }
        let mut next_record = self.clone();
        next_record.state = next;
        Ok(next_record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment() -> DeploymentRecord {
        DeploymentRecord::new(
            DeploymentId::generate(),
            VersionId::generate(),
            LineageId::generate(),
            crate::domain::TargetId::new("web").unwrap(),
            Timestamp::now(),
        )
    }

    #[test]
    fn happy_path_transitions() {
        let record = deployment();
        let staged = record
            .transition(DeploymentState::Staging)
            .unwrap()
            .transition(DeploymentState::Staged)
            .unwrap()
            .transition(DeploymentState::Activating)
            .unwrap()
            .transition(DeploymentState::Active)
            .unwrap()
            .transition(DeploymentState::Healthy)
            .unwrap();
        assert!(staged.state.is_success());
    }

    #[test]
    fn failure_and_rollback_transitions() {
        let record = deployment();
        let failed = record
            .transition(DeploymentState::Staging)
            .unwrap()
            .transition(DeploymentState::Failed)
            .unwrap();
        assert!(failed.transition(DeploymentState::Healthy).is_err());
        let rolled = failed
            .transition(DeploymentState::RollingBack)
            .unwrap()
            .transition(DeploymentState::RolledBack)
            .unwrap();
        assert_eq!(rolled.state, DeploymentState::RolledBack);
    }

    #[test]
    fn pending_cannot_activate_directly() {
        let record = deployment();
        assert!(record.transition(DeploymentState::Activating).is_err());
        assert!(record.transition(DeploymentState::Active).is_err());
    }

    #[test]
    fn deployment_json_roundtrip() {
        let record = deployment();
        let json = serde_json::to_string(&record).unwrap();
        let back: DeploymentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }
}
