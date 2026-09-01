//! Orchestrator module for high-level workflow management
//!
//! This module provides the `Orchestrator` trait and implementations for coordinating
//! the various components of the ACME client to perform complex tasks like
//! certificate issuance, renewal, and revocation.

pub mod provisioner;
pub mod renewer;
pub mod validator;

use crate::config::Config;
use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Status of an orchestration task
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OrchestrationStatus {
    Pending,
    InProgress { progress: f32, message: String },
    Completed,
    Failed(String),
}

impl OrchestrationStatus {
    /// Maps a durable [`OperationStatus`](crate::domain::OperationStatus)
    /// onto the legacy orchestration view.
    ///
    /// The operation repository is the source of truth as of v0.9; this
    /// mapping exists so old callers keep their status shape during the
    /// migration period (roadmap T03/T08).
    pub fn from_operation(
        status: crate::domain::OperationStatus,
        steps_completed: usize,
        steps_total: usize,
    ) -> Self {
        let progress = if steps_total == 0 {
            1.0
        } else {
            steps_completed as f32 / steps_total as f32
        };
        match status {
            crate::domain::OperationStatus::Queued => OrchestrationStatus::Pending,
            crate::domain::OperationStatus::Running => OrchestrationStatus::InProgress {
                progress,
                message: "running".to_string(),
            },
            crate::domain::OperationStatus::Waiting => OrchestrationStatus::InProgress {
                progress,
                message: "waiting for external event".to_string(),
            },
            crate::domain::OperationStatus::Succeeded => OrchestrationStatus::Completed,
            crate::domain::OperationStatus::Failed
            | crate::domain::OperationStatus::CompensationFailed => {
                OrchestrationStatus::Failed(format!("{:?}", status))
            }
            crate::domain::OperationStatus::CancelRequested
            | crate::domain::OperationStatus::Compensating => OrchestrationStatus::InProgress {
                progress,
                message: "cancelling".to_string(),
            },
            crate::domain::OperationStatus::Cancelled => {
                OrchestrationStatus::Failed("cancelled".to_string())
            }
        }
    }
}

/// Orchestrator trait for executing workflows
#[async_trait]
pub trait Orchestrator: Send + Sync {
    /// Execute the orchestration workflow
    async fn execute(&self, config: &Config) -> Result<()>;

    /// Get current status of the task
    fn status(&self) -> OrchestrationStatus {
        OrchestrationStatus::Pending
    }

    /// Cancel the ongoing task
    async fn cancel(&self) -> Result<()> {
        Ok(())
    }
}

pub use provisioner::CertificateProvisioner;
pub use renewer::CertificateRenewer;
pub use validator::DomainValidator;
