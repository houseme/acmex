//! Orchestrator module for high-level workflow management
//!
//! This module provides the `Orchestrator` trait and implementations for coordinating
//! the various components of the ACME client to perform complex tasks like
//! certificate issuance, renewal, and revocation.

pub mod provisioner;
pub mod validator;

use crate::config::Config;
use crate::error::Result;
use async_trait::async_trait;

/// Orchestrator trait for executing workflows
#[async_trait]
pub trait Orchestrator: Send + Sync {
    /// Execute the orchestration workflow
    async fn execute(&self, config: &Config) -> Result<()>;
}

pub use provisioner::CertificateProvisioner;
pub use validator::DomainValidator;
