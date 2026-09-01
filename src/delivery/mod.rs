//! Downstream delivery: the `CertificateSink` port.
//!
//! Issuance and delivery are decoupled: a certificate version is persisted
//! first (immutable), then *staged* at each target without touching the
//! live pointer, *activated* atomically, *health-checked* against the
//! version fingerprint, and *rolled back* on failure. Deployment state
//! lives in [`DeploymentRecord`]s (T02) and blocks the lineage's
//! active-version switch only per the intent's delivery requirement.

pub mod file_sink;
pub mod http_sink;
pub mod material;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::domain::{CertificateVersion, DeliveryRequirement, DeploymentId, TargetId, VersionId};
use crate::error::Result;

pub use file_sink::FileSink;
pub use http_sink::HttpAgentSink;
pub use material::{CertificateMaterial, CertificateMaterialBuilder, MaterialFormat};

/// What to deploy where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSpec {
    /// The delivery target id from the intent.
    pub target_id: TargetId,
    /// Sink-specific reference (directory path, secret name, agent URL...).
    pub reference: String,
    /// Whether this target gates activation of the lineage's new version.
    pub requirement: DeliveryRequirement,
}

/// A staged (not yet live) deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedDeployment {
    /// The sink that staged it.
    pub sink_id: String,
    /// The deployed version.
    pub version_id: VersionId,
    /// Sink-specific staging reference (e.g. version directory).
    pub staged_ref: String,
    /// The deployment record identity (for state persistence).
    pub deployment_id: Option<DeploymentId>,
}

/// Health of a deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentHealth {
    /// Whether the target serves exactly the staged version.
    pub healthy: bool,
    /// Diagnostic detail (no secrets).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Cleanup outcome for old versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkCleanupOutcome {
    /// Artifacts removed.
    Removed,
    /// Nothing to remove.
    AlreadyAbsent,
}

/// The delivery port.
#[async_trait]
pub trait CertificateSink: Send + Sync {
    /// Sink identity (`file`, `http-agent`, ...).
    fn sink_id(&self) -> &str;

    /// Writes the version without touching the live pointer. Idempotent.
    async fn stage(
        &self,
        spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: &CertificateMaterial,
    ) -> Result<StagedDeployment>;

    /// Switches the target to the staged version atomically.
    async fn activate(&self, staged: &StagedDeployment) -> Result<()>;

    /// Verifies the target serves exactly this version.
    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth>;

    /// Restores the previous version.
    async fn rollback(&self, staged: &StagedDeployment) -> Result<()>;

    /// Removes old staged artifacts. Idempotent.
    async fn cleanup(&self, staged: &StagedDeployment) -> Result<SinkCleanupOutcome>;
}

/// Aggregates deployment outcomes against a delivery requirement.
pub fn requirement_satisfied(
    requirement: &DeliveryRequirement,
    healthy: usize,
    failed: usize,
) -> bool {
    match requirement {
        DeliveryRequirement::Required => failed == 0 && healthy > 0,
        DeliveryRequirement::Quorum(n) => healthy >= *n,
        DeliveryRequirement::BestEffort => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirement_aggregation() {
        assert!(requirement_satisfied(&DeliveryRequirement::Required, 2, 0));
        assert!(!requirement_satisfied(&DeliveryRequirement::Required, 2, 1));
        assert!(!requirement_satisfied(&DeliveryRequirement::Required, 0, 0));
        assert!(requirement_satisfied(&DeliveryRequirement::Quorum(2), 2, 1));
        assert!(!requirement_satisfied(
            &DeliveryRequirement::Quorum(2),
            1,
            0
        ));
        assert!(requirement_satisfied(
            &DeliveryRequirement::BestEffort,
            0,
            3
        ));
    }
}
