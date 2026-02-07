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
