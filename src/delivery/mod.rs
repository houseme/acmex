//! Certificate material rendering and downstream delivery sinks.

pub mod http_sink;

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs;
use x509_parser::prelude::*;

use crate::domain::{
    CertificateLineage, CertificateVersion, DeliveryRequirement, DeliveryTargetKind, DeploymentId,
    DeploymentRecord, DeploymentState, OperationId, OperationKind, OperationRecord,
    OperationStatus, OperationSubject, StepStatus, TargetId, VersionId, VersionState,
    WorkflowStepKind,
};
use crate::error::{AcmeError, Result};
use crate::key::SecretBytes;
use crate::repository::{CasOutcome, CreateOutcome, RepositorySet};

pub use http_sink::HttpAgentSink;

/// Rendered certificate material for a sink invocation.
#[derive(Clone, PartialEq, Eq)]
pub struct CertificateMaterial {
    /// PEM leaf plus intermediates.
    pub fullchain_pem: String,
    /// PEM leaf certificate only.
    pub cert_pem: String,
    /// Optional private key PEM for sinks that install TLS keypairs.
    pub private_key_pem: Option<SecretBytes>,
    /// SHA-256 fingerprint of the leaf certificate DER.
    pub leaf_sha256: String,
}

impl fmt::Debug for CertificateMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateMaterial")
            .field("fullchain_len", &self.fullchain_pem.len())
            .field("cert_len", &self.cert_pem.len())
            .field("has_private_key", &self.private_key_pem.is_some())
            .field("leaf_sha256", &self.leaf_sha256)
            .finish()
    }
}

/// Builder that centralizes certificate/key rendering and verification.
#[derive(Debug, Clone)]
pub struct CertificateMaterialBuilder {
    require_private_key: bool,
}

impl CertificateMaterialBuilder {
    /// Creates a builder that allows keyless material.
    pub fn new() -> Self {
        Self {
            require_private_key: false,
        }
    }

    /// Requires a private key and verifies it matches the leaf certificate.
    pub fn require_private_key(mut self) -> Self {
        self.require_private_key = true;
        self
    }

    /// Builds material from a certificate version and optional private key.
    pub fn build(
        &self,
        version: &CertificateVersion,
        private_key_pem: Option<SecretBytes>,
    ) -> Result<CertificateMaterial> {
        if self.require_private_key && private_key_pem.is_none() {
            return Err(AcmeError::invalid_input(
                "certificate sink requires private key material",
            ));
        }
        let certs = ::pem::parse_many(version.certificate_chain_pem.as_bytes())
            .map_err(|err| AcmeError::certificate(format!("parse certificate chain: {err}")))?;
        let leaf = certs
            .iter()
            .find(|block| block.tag() == "CERTIFICATE")
            .ok_or_else(|| AcmeError::certificate("certificate chain is empty"))?;
        let cert_pem = ::pem::encode_config(
            &::pem::Pem::new("CERTIFICATE", leaf.contents().to_vec()),
            ::pem::EncodeConfig::new().set_line_ending(::pem::LineEnding::LF),
        );
        let leaf_sha256 = sha256_hex(leaf.contents());
        if let Some(key) = private_key_pem.as_ref() {
            verify_key_matches_certificate(key.expose_secret(), leaf.contents())?;
        }
        Ok(CertificateMaterial {
            fullchain_pem: version.certificate_chain_pem.clone(),
            cert_pem,
            private_key_pem,
            leaf_sha256,
        })
    }
}

impl Default for CertificateMaterialBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Borrowed material passed to a sink for one operation.
#[derive(Debug, Clone, Copy)]
pub struct CertificateMaterialRef<'a> {
    /// Rendered material.
    pub material: &'a CertificateMaterial,
}

/// One delivery target invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSpec {
    /// Target identity.
    pub target_id: TargetId,
    /// Sink type.
    pub kind: DeliveryTargetKind,
    /// Opaque target reference.
    pub reference: String,
    /// Whether this target gates lineage activation.
    pub requirement: DeliveryRequirement,
}

/// Sink-specific staged deployment pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedDeployment {
    /// Sink type.
    pub kind: DeliveryTargetKind,
    /// Target identity.
    pub target_id: TargetId,
    /// Version being deployed.
    pub version_id: VersionId,
    /// Sink-local staged reference.
    pub staged_ref: String,
    /// Previous active sink pointer, used for rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_active_ref: Option<String>,
    /// Material fingerprint staged by the sink.
    pub leaf_sha256: String,
    /// Optimistic version for remote/agent sinks.
    #[serde(default)]
    pub resource_version: u64,
}

/// Health check result for one sink target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentHealth {
    /// Active target serves the expected material.
    Healthy,
    /// Target is reachable but serves other material.
    Unhealthy(String),
    /// Target cannot currently be observed.
    Unknown(String),
}

/// Cleanup result for staged or old artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupOutcome {
    /// Something was removed.
    Cleaned,
    /// Nothing needed removal.
    AlreadyClean,
}

/// Downstream delivery lifecycle.
#[async_trait]
pub trait CertificateSink: Send + Sync {
    /// Writes versioned material without switching active traffic.
    async fn stage(
        &self,
        spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: CertificateMaterialRef<'_>,
    ) -> Result<StagedDeployment>;

    /// Atomically switches the target to the staged material.
    async fn activate(&self, staged: &StagedDeployment) -> Result<()>;
    /// Observes whether the active target serves the staged fingerprint.
    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth>;
    /// Restores the previous active target.
    async fn rollback(&self, staged: &StagedDeployment) -> Result<()>;
    /// Cleans staged artifacts.
    async fn cleanup(&self, staged: &StagedDeployment) -> Result<CleanupOutcome>;
}

/// Result of checking whether deployments allow active-version promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentGate {
    /// Whether all activation requirements are satisfied.
    pub satisfied: bool,
    /// Required/quorum targets still blocking activation.
    pub missing_targets: Vec<TargetId>,
}

/// Outcome of attempting to activate a version after deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum DeploymentActivationOutcome {
    /// Deployment policy is still waiting for target health.
    Waiting {
        /// Lineage that owns the version.
        lineage_id: crate::domain::LineageId,
        /// Version waiting for deployment.
        version_id: VersionId,
        /// Blocking targets.
        missing_targets: Vec<TargetId>,
    },
    /// Version was already active.
    AlreadyActive {
        /// Lineage that owns the version.
        lineage_id: crate::domain::LineageId,
        /// Version already active.
        version_id: VersionId,
    },
    /// Version was promoted.
    Activated {
        /// Lineage that owns the version.
        lineage_id: crate::domain::LineageId,
        /// Newly active version.
        version_id: VersionId,
        /// Previous active version, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        superseded_version_id: Option<VersionId>,
    },
}

/// Durable deployment orchestration for the post-issuance delivery phase.
#[derive(Clone)]
pub struct DeploymentOrchestrator {
    repositories: RepositorySet,
    sinks: HashMap<&'static str, Arc<dyn CertificateSink>>,
}

impl fmt::Debug for DeploymentOrchestrator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeploymentOrchestrator")
            .field("sinks", &self.sinks.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl DeploymentOrchestrator {
    /// Creates an orchestrator over a repository set.
    pub fn new(repositories: RepositorySet) -> Self {
        Self {
            repositories,
            sinks: HashMap::new(),
        }
    }

    /// Registers a sink implementation for a delivery target kind.
    pub fn register_sink(
        mut self,
        kind: DeliveryTargetKind,
        sink: Arc<dyn CertificateSink>,
    ) -> Self {
        self.sinks.insert(sink_key(kind), sink);
        self
    }

    /// Returns the backing repositories.
    pub fn repositories(&self) -> &RepositorySet {
        &self.repositories
    }

    /// Creates one deployment record and child `Deploy` operation per target.
    pub async fn schedule_deployments_for_version(
        &self,
        version_id: &VersionId,
        selected_targets: &[TargetId],
    ) -> Result<Vec<DeploymentRecord>> {
        let (version, lineage, intent) = self.version_lineage_intent(version_id).await?;
        let selected: BTreeSet<TargetId> = selected_targets.iter().cloned().collect();
        let mut scheduled = Vec::new();

        for target in intent.delivery_targets {
            if !selected.is_empty() && !selected.contains(&target.id) {
                continue;
            }
            let deployment_id = deployment_id_for(version_id, &target.id)?;
            let deployment = DeploymentRecord::new(
                deployment_id.clone(),
                version.id.clone(),
                lineage.id.clone(),
                target.id.clone(),
                self.repositories.clock.now(),
            );
            let persisted = match self
                .repositories
                .deployments
                .create(deployment.clone())
                .await?
            {
                CreateOutcome::Created => {
                    self.repositories
                        .outbox
                        .append(
                            "deployment.scheduled",
                            serde_json::json!({
                                "deployment_id": deployment.id.as_str(),
                                "version_id": version.id.as_str(),
                                "lineage_id": lineage.id.as_str(),
                                "target_id": target.id.as_str(),
                                "target_kind": sink_key(target.kind),
                            }),
                            None,
                        )
                        .await?;
                    deployment
                }
                CreateOutcome::AlreadyExists => self
                    .repositories
                    .deployments
                    .get(&deployment_id)
                    .await?
                    .map(|stored| stored.value)
                    .ok_or_else(|| {
                        AcmeError::storage(format!(
                            "deployment `{deployment_id}` disappeared after idempotent create"
                        ))
                    })?,
            };
            self.ensure_deploy_operation(&persisted, &intent.id).await?;
            scheduled.push(persisted);
        }
        Ok(scheduled)
    }

    /// Advances one target deployment by one durable state transition.
    pub async fn run_deployment_once(
        &self,
        deployment_id: &DeploymentId,
        material: &CertificateMaterial,
    ) -> Result<DeploymentRecord> {
        let stored = self
            .repositories
            .deployments
            .get(deployment_id)
            .await?
            .ok_or_else(|| {
                AcmeError::not_found(format!("deployment `{deployment_id}` not found"))
            })?;
        let version = self
            .repositories
            .versions
            .get(&stored.value.version_id)
            .await?
            .map(|stored| stored.value)
            .ok_or_else(|| {
                AcmeError::storage(format!(
                    "deployment `{deployment_id}` references missing version `{}`",
                    stored.value.version_id
                ))
            })?;
        let spec = self.deployment_spec(&stored.value).await?;
        let sink = self.sink(spec.kind)?;

        match stored.value.state {
            DeploymentState::Pending | DeploymentState::Failed => {
                let staging = self
                    .transition_deployment(&stored, DeploymentState::Staging, None, None)
                    .await?;
                let staged = sink
                    .stage(&spec, &version, CertificateMaterialRef { material })
                    .await;
                match staged {
                    Ok(staged) => {
                        let staged_ref = serde_json::to_string(&staged)?;
                        let record = self
                            .transition_deployment(
                                &self.reload_deployment(&staging.id).await?,
                                DeploymentState::Staged,
                                Some(staged_ref),
                                None,
                            )
                            .await?;
                        self.record_deploy_operation_step(
                            &record,
                            WorkflowStepKind::StageDeployment,
                            true,
                            None,
                        )
                        .await?;
                        self.emit_deployment_event(&record, "deployment.staged", None)
                            .await?;
                        Ok(record)
                    }
                    Err(err) => {
                        let record = self
                            .transition_deployment(
                                &self.reload_deployment(&staging.id).await?,
                                DeploymentState::Failed,
                                None,
                                Some(err.to_string()),
                            )
                            .await?;
                        self.record_deploy_operation_step(
                            &record,
                            WorkflowStepKind::StageDeployment,
                            false,
                            Some(&err),
                        )
                        .await?;
                        self.finish_deploy_operation(&record, OperationStatus::Failed, Some(&err))
                            .await?;
                        self.emit_deployment_event(&record, "deployment.failed", Some(&err))
                            .await?;
                        Ok(record)
                    }
                }
            }
            DeploymentState::Staged => {
                let activating = self
                    .transition_deployment(&stored, DeploymentState::Activating, None, None)
                    .await?;
                let staged = decode_staged(&activating)?;
                match sink.activate(&staged).await {
                    Ok(()) => {
                        let record = self
                            .transition_deployment(
                                &self.reload_deployment(&activating.id).await?,
                                DeploymentState::Active,
                                None,
                                None,
                            )
                            .await?;
                        self.record_deploy_operation_step(
                            &record,
                            WorkflowStepKind::ActivateDeployment,
                            true,
                            None,
                        )
                        .await?;
                        self.emit_deployment_event(&record, "deployment.activated", None)
                            .await?;
                        Ok(record)
                    }
                    Err(err) => {
                        let _ = sink.rollback(&staged).await;
                        let record = self
                            .transition_deployment(
                                &self.reload_deployment(&activating.id).await?,
                                DeploymentState::Failed,
                                None,
                                Some(err.to_string()),
                            )
                            .await?;
                        self.record_deploy_operation_step(
                            &record,
                            WorkflowStepKind::ActivateDeployment,
                            false,
                            Some(&err),
                        )
                        .await?;
                        self.finish_deploy_operation(&record, OperationStatus::Failed, Some(&err))
                            .await?;
                        self.emit_deployment_event(&record, "deployment.failed", Some(&err))
                            .await?;
                        Ok(record)
                    }
                }
            }
            DeploymentState::Active => {
                let staged = decode_staged(&stored.value)?;
                match sink.health_check(&staged).await? {
                    DeploymentHealth::Healthy => {
                        let record = self
                            .transition_deployment(&stored, DeploymentState::Healthy, None, None)
                            .await?;
                        self.record_deploy_operation_step(
                            &record,
                            WorkflowStepKind::VerifyDeployment,
                            true,
                            None,
                        )
                        .await?;
                        self.finish_deploy_operation(&record, OperationStatus::Succeeded, None)
                            .await?;
                        self.emit_deployment_event(&record, "deployment.healthy", None)
                            .await?;
                        Ok(record)
                    }
                    DeploymentHealth::Unhealthy(reason) | DeploymentHealth::Unknown(reason) => {
                        let _ = sink.rollback(&staged).await;
                        let rolling_back = self
                            .transition_deployment(
                                &stored,
                                DeploymentState::RollingBack,
                                None,
                                Some(reason.clone()),
                            )
                            .await?;
                        let record = self
                            .transition_deployment(
                                &self.reload_deployment(&rolling_back.id).await?,
                                DeploymentState::RolledBack,
                                None,
                                Some(reason),
                            )
                            .await?;
                        let error = AcmeError::certificate("deployment health check failed");
                        self.record_deploy_operation_step(
                            &record,
                            WorkflowStepKind::VerifyDeployment,
                            false,
                            Some(&error),
                        )
                        .await?;
                        self.finish_deploy_operation(
                            &record,
                            OperationStatus::Failed,
                            Some(&error),
                        )
                        .await?;
                        self.emit_deployment_event(&record, "deployment.rolled_back", Some(&error))
                            .await?;
                        Ok(record)
                    }
                }
            }
            DeploymentState::Healthy
            | DeploymentState::RollingBack
            | DeploymentState::RolledBack
            | DeploymentState::RollbackFailed
            | DeploymentState::CleanupPending
            | DeploymentState::Cleaned
            | DeploymentState::Staging
            | DeploymentState::Activating => Ok(stored.value),
        }
    }

    /// Checks whether deployment policy permits active-version promotion.
    pub async fn activation_gate(&self, version_id: &VersionId) -> Result<DeploymentGate> {
        let (_, _, intent) = self.version_lineage_intent(version_id).await?;
        if intent.delivery_targets.is_empty() {
            return Ok(DeploymentGate {
                satisfied: true,
                missing_targets: Vec::new(),
            });
        }
        let deployments = self
            .repositories
            .deployments
            .list_by_version(version_id)
            .await?;
        let successful_targets: BTreeSet<TargetId> = deployments
            .into_iter()
            .filter(|stored| stored.value.state.is_success())
            .map(|stored| stored.value.target_id)
            .collect();
        let quorum_successes = intent
            .delivery_targets
            .iter()
            .filter(|target| matches!(target.requirement, DeliveryRequirement::Quorum(_)))
            .filter(|target| successful_targets.contains(&target.id))
            .count();
        let mut missing = Vec::new();
        for target in &intent.delivery_targets {
            match target.requirement {
                DeliveryRequirement::Required => {
                    if !successful_targets.contains(&target.id) {
                        missing.push(target.id.clone());
                    }
                }
                DeliveryRequirement::Quorum(required) => {
                    if quorum_successes < required {
                        missing.push(target.id.clone());
                    }
                }
                DeliveryRequirement::BestEffort => {}
            }
        }
        missing.sort();
        missing.dedup();
        Ok(DeploymentGate {
            satisfied: missing.is_empty(),
            missing_targets: missing,
        })
    }

    /// Promotes a version only after deployment requirements are satisfied.
    pub async fn activate_version_when_deployments_satisfied(
        &self,
        version_id: &VersionId,
    ) -> Result<DeploymentActivationOutcome> {
        let (version, lineage, _) = self.version_lineage_intent(version_id).await?;
        if lineage.active_version_id.as_ref() == Some(version_id) {
            return Ok(DeploymentActivationOutcome::AlreadyActive {
                lineage_id: lineage.id,
                version_id: version_id.clone(),
            });
        }
        let gate = self.activation_gate(version_id).await?;
        if !gate.satisfied {
            return Ok(DeploymentActivationOutcome::Waiting {
                lineage_id: lineage.id,
                version_id: version_id.clone(),
                missing_targets: gate.missing_targets,
            });
        }
        let active_version = self.mark_version_active(version_id).await?;
        let previous_active = lineage.active_version_id.clone();
        let updated_lineage = self
            .activate_lineage_version(&lineage, &active_version)
            .await?;
        if let Some(previous) = previous_active.as_ref() {
            self.supersede_previous_version(previous, version_id)
                .await?;
        }
        self.repositories
            .outbox
            .append(
                "deployment.version_activated",
                serde_json::json!({
                    "lineage_id": updated_lineage.id.as_str(),
                    "version_id": version.id.as_str(),
                    "superseded_version_id": previous_active.as_ref().map(|id| id.as_str()),
                }),
                None,
            )
            .await?;
        Ok(DeploymentActivationOutcome::Activated {
            lineage_id: updated_lineage.id,
            version_id: version_id.clone(),
            superseded_version_id: previous_active,
        })
    }

    async fn version_lineage_intent(
        &self,
        version_id: &VersionId,
    ) -> Result<(
        CertificateVersion,
        CertificateLineage,
        crate::domain::CertificateIntent,
    )> {
        let version = self
            .repositories
            .versions
            .get(version_id)
            .await?
            .map(|stored| stored.value)
            .ok_or_else(|| AcmeError::not_found(format!("version `{version_id}` not found")))?;
        let lineage = self
            .repositories
            .lineages
            .get(&version.lineage_id)
            .await?
            .map(|stored| stored.value)
            .ok_or_else(|| {
                AcmeError::storage(format!(
                    "version `{version_id}` references missing lineage `{}`",
                    version.lineage_id
                ))
            })?;
        let intent = self
            .repositories
            .intents
            .get(&lineage.intent_id)
            .await?
            .map(|stored| stored.value)
            .ok_or_else(|| {
                AcmeError::storage(format!(
                    "lineage `{}` references missing intent `{}`",
                    lineage.id, lineage.intent_id
                ))
            })?;
        Ok((version, lineage, intent))
    }

    async fn ensure_deploy_operation(
        &self,
        deployment: &DeploymentRecord,
        intent_id: &crate::domain::IntentId,
    ) -> Result<()> {
        let operation = OperationRecord::new(
            deploy_operation_id_for(&deployment.version_id, &deployment.target_id)?,
            OperationKind::Deploy,
            OperationSubject {
                intent_id: Some(intent_id.clone()),
                lineage_id: Some(deployment.lineage_id.clone()),
                version_id: Some(deployment.version_id.clone()),
            },
            Some(format!(
                "deploy:{}:{}",
                deployment.version_id, deployment.target_id
            )),
            Some(hash_json(&serde_json::json!({
                "version_id": deployment.version_id.as_str(),
                "target_id": deployment.target_id.as_str(),
            }))),
            self.repositories.clock.now(),
        );
        self.repositories.operations.create(operation).await?;
        Ok(())
    }

    async fn deployment_spec(&self, deployment: &DeploymentRecord) -> Result<DeploymentSpec> {
        let (_, _, intent) = self.version_lineage_intent(&deployment.version_id).await?;
        let target = intent
            .delivery_targets
            .into_iter()
            .find(|target| target.id == deployment.target_id)
            .ok_or_else(|| {
                AcmeError::storage(format!(
                    "deployment `{}` references unknown target `{}`",
                    deployment.id, deployment.target_id
                ))
            })?;
        Ok(DeploymentSpec {
            target_id: target.id,
            kind: target.kind,
            reference: target.reference,
            requirement: target.requirement,
        })
    }

    fn sink(&self, kind: DeliveryTargetKind) -> Result<Arc<dyn CertificateSink>> {
        self.sinks
            .get(sink_key(kind))
            .cloned()
            .ok_or_else(|| AcmeError::configuration(format!("no sink registered for {:?}", kind)))
    }

    async fn reload_deployment(
        &self,
        deployment_id: &DeploymentId,
    ) -> Result<crate::repository::Versioned<DeploymentRecord>> {
        self.repositories
            .deployments
            .get(deployment_id)
            .await?
            .ok_or_else(|| AcmeError::not_found(format!("deployment `{deployment_id}` not found")))
    }

    async fn transition_deployment(
        &self,
        stored: &crate::repository::Versioned<DeploymentRecord>,
        next: DeploymentState,
        staged_ref: Option<String>,
        error: Option<String>,
    ) -> Result<DeploymentRecord> {
        let mut record = stored.value.transition(next).map_err(AcmeError::storage)?;
        if let Some(staged_ref) = staged_ref {
            record.staged_ref = Some(staged_ref);
        }
        record.last_error = error;
        record.updated_at = self.repositories.clock.now();
        if matches!(
            next,
            DeploymentState::Staging | DeploymentState::Activating | DeploymentState::RollingBack
        ) {
            record.attempts += 1;
        }
        self.repositories
            .deployments
            .update(stored.revision, record.clone())
            .await?
            .expect_updated()?;
        Ok(record)
    }

    async fn record_deploy_operation_step(
        &self,
        deployment: &DeploymentRecord,
        step: WorkflowStepKind,
        success: bool,
        error: Option<&AcmeError>,
    ) -> Result<()> {
        let op_id = deploy_operation_id_for(&deployment.version_id, &deployment.target_id)?;
        let Some(stored) = self.repositories.operations.get(&op_id).await? else {
            return Ok(());
        };
        let mut op = stored.value;
        if op.status == OperationStatus::Queued {
            op = op
                .transition(OperationStatus::Running)
                .map_err(AcmeError::storage)?;
        }
        if let Some((index, step_record)) = op
            .steps
            .iter_mut()
            .enumerate()
            .find(|(_, candidate)| candidate.kind == step)
        {
            step_record.attempt += 1;
            step_record.status = if success {
                StepStatus::Completed
            } else {
                StepStatus::Failed
            };
            step_record.finished_at = Some(self.repositories.clock.now());
            step_record.output_ref = Some(deployment.id.as_str().to_string());
            step_record.error = error.map(|err| crate::domain::ClassifiedError {
                code: crate::domain::error_codes::INTERNAL,
                class: crate::domain::ErrorClass::Retryable,
                detail: Some(err.to_string()),
            });
            if success && op.current_step_index <= index {
                op.current_step_index = (index + 1).min(op.steps.len().saturating_sub(1));
            }
        }
        op.updated_at = self.repositories.clock.now();
        self.repositories
            .operations
            .update(stored.revision, op)
            .await?
            .expect_updated()?;
        Ok(())
    }

    async fn finish_deploy_operation(
        &self,
        deployment: &DeploymentRecord,
        status: OperationStatus,
        error: Option<&AcmeError>,
    ) -> Result<()> {
        let op_id = deploy_operation_id_for(&deployment.version_id, &deployment.target_id)?;
        let Some(stored) = self.repositories.operations.get(&op_id).await? else {
            return Ok(());
        };
        if stored.value.status.is_terminal() {
            return Ok(());
        }
        let mut op = stored
            .value
            .transition(status)
            .map_err(AcmeError::storage)?;
        op.error = error.map(|err| crate::domain::ClassifiedError {
            code: crate::domain::error_codes::INTERNAL,
            class: crate::domain::ErrorClass::Terminal,
            detail: Some(err.to_string()),
        });
        op.updated_at = self.repositories.clock.now();
        self.repositories
            .operations
            .update(stored.revision, op)
            .await?
            .expect_updated()?;
        self.repositories
            .outbox
            .append(
                "operation.finished",
                serde_json::json!({
                    "operation_id": op_id.as_str(),
                    "status": status.as_str(),
                    "deployment_id": deployment.id.as_str(),
                }),
                None,
            )
            .await?;
        Ok(())
    }

    async fn emit_deployment_event(
        &self,
        deployment: &DeploymentRecord,
        event_type: &str,
        error: Option<&AcmeError>,
    ) -> Result<()> {
        self.repositories
            .outbox
            .append(
                event_type,
                serde_json::json!({
                    "deployment_id": deployment.id.as_str(),
                    "version_id": deployment.version_id.as_str(),
                    "lineage_id": deployment.lineage_id.as_str(),
                    "target_id": deployment.target_id.as_str(),
                    "state": deployment.state.as_str(),
                    "error": error.map(ToString::to_string),
                }),
                None,
            )
            .await?;
        Ok(())
    }

    async fn mark_version_active(&self, version_id: &VersionId) -> Result<CertificateVersion> {
        loop {
            let stored = self
                .repositories
                .versions
                .get(version_id)
                .await?
                .ok_or_else(|| AcmeError::not_found(format!("version `{version_id}` not found")))?;
            let next = stored.value.transition(VersionState::Active)?;
            match self
                .repositories
                .versions
                .update(stored.revision, next.clone())
                .await?
            {
                CasOutcome::Updated(_) => return Ok(next),
                CasOutcome::Conflict { .. } => continue,
            }
        }
    }

    async fn activate_lineage_version(
        &self,
        lineage: &CertificateLineage,
        version: &CertificateVersion,
    ) -> Result<CertificateLineage> {
        loop {
            let stored = self
                .repositories
                .lineages
                .get(&lineage.id)
                .await?
                .ok_or_else(|| {
                    AcmeError::not_found(format!("lineage `{}` not found", lineage.id))
                })?;
            let next = stored.value.activate_version(version)?;
            match self
                .repositories
                .lineages
                .update(stored.revision, next.clone())
                .await?
            {
                CasOutcome::Updated(_) => return Ok(next),
                CasOutcome::Conflict { .. } => continue,
            }
        }
    }

    async fn supersede_previous_version(
        &self,
        previous_version_id: &VersionId,
        successor_id: &VersionId,
    ) -> Result<()> {
        loop {
            let Some(stored) = self.repositories.versions.get(previous_version_id).await? else {
                return Ok(());
            };
            if stored.value.state == VersionState::Superseded
                && stored.value.superseded_by.as_ref() == Some(successor_id)
            {
                return Ok(());
            }
            let next = stored.value.superseded_by(successor_id.clone())?;
            match self
                .repositories
                .versions
                .update(stored.revision, next)
                .await?
            {
                CasOutcome::Updated(_) => return Ok(()),
                CasOutcome::Conflict { .. } => continue,
            }
        }
    }
}

/// Versioned filesystem sink using `versions/<id>` and an atomic `current` pointer.
#[derive(Debug, Clone)]
pub struct FileCertificateSink;

impl FileCertificateSink {
    /// Creates a file sink.
    pub fn new() -> Self {
        Self
    }
}

impl Default for FileCertificateSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CertificateSink for FileCertificateSink {
    async fn stage(
        &self,
        spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: CertificateMaterialRef<'_>,
    ) -> Result<StagedDeployment> {
        if spec.kind != DeliveryTargetKind::File {
            return Err(AcmeError::invalid_input("file sink requires file target"));
        }
        let root = PathBuf::from(&spec.reference);
        let versions = root.join("versions");
        let version_dir = versions.join(version.id.as_str());
        fs::create_dir_all(&version_dir).await?;
        write_material_file(
            &version_dir.join("fullchain.pem"),
            material.material.fullchain_pem.as_bytes(),
            0o644,
        )
        .await?;
        write_material_file(
            &version_dir.join("cert.pem"),
            material.material.cert_pem.as_bytes(),
            0o644,
        )
        .await?;
        if let Some(key) = material.material.private_key_pem.as_ref() {
            write_material_file(&version_dir.join("key.pem"), key.expose_secret(), 0o600).await?;
        }
        let metadata = serde_json::json!({
            "version_id": version.id.as_str(),
            "target_id": spec.target_id.as_str(),
            "leaf_sha256": material.material.leaf_sha256,
            "key_provider": version.key_ref.provider,
            "key_id": version.key_ref.key_id.as_str(),
        });
        write_material_file(
            &version_dir.join("metadata.json"),
            serde_json::to_vec_pretty(&metadata)?.as_slice(),
            0o644,
        )
        .await?;
        sync_dir(&version_dir)?;
        sync_dir(&versions)?;
        let previous_active_ref = current_target(&root).await?;
        Ok(StagedDeployment {
            kind: spec.kind,
            target_id: spec.target_id.clone(),
            version_id: version.id.clone(),
            staged_ref: version_dir.to_string_lossy().into_owned(),
            previous_active_ref,
            leaf_sha256: material.material.leaf_sha256.clone(),
            resource_version: 0,
        })
    }

    async fn activate(&self, staged: &StagedDeployment) -> Result<()> {
        let version_dir = PathBuf::from(&staged.staged_ref);
        let root = version_dir
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| AcmeError::invalid_input("invalid staged file sink reference"))?;
        set_current(root, &version_dir).await
    }

    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth> {
        let version_dir = PathBuf::from(&staged.staged_ref);
        let root = version_dir
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| AcmeError::invalid_input("invalid staged file sink reference"))?;
        let Some(current) = current_target(root).await? else {
            return Ok(DeploymentHealth::Unknown(
                "current pointer is absent".into(),
            ));
        };
        if current != staged.staged_ref {
            return Ok(DeploymentHealth::Unhealthy(format!(
                "current points at {current}, expected {}",
                staged.staged_ref
            )));
        }
        let metadata = fs::read(version_dir.join("metadata.json")).await?;
        let metadata: serde_json::Value = serde_json::from_slice(&metadata)?;
        if metadata
            .get("leaf_sha256")
            .and_then(serde_json::Value::as_str)
            == Some(staged.leaf_sha256.as_str())
        {
            Ok(DeploymentHealth::Healthy)
        } else {
            Ok(DeploymentHealth::Unhealthy(
                "active metadata fingerprint mismatch".into(),
            ))
        }
    }

    async fn rollback(&self, staged: &StagedDeployment) -> Result<()> {
        let version_dir = PathBuf::from(&staged.staged_ref);
        let root = version_dir
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| AcmeError::invalid_input("invalid staged file sink reference"))?;
        match staged.previous_active_ref.as_ref() {
            Some(previous) => set_current(root, &PathBuf::from(previous)).await,
            None => remove_current(root).await,
        }
    }

    async fn cleanup(&self, staged: &StagedDeployment) -> Result<CleanupOutcome> {
        let path = PathBuf::from(&staged.staged_ref);
        if path.exists() {
            fs::remove_dir_all(path).await?;
            Ok(CleanupOutcome::Cleaned)
        } else {
            Ok(CleanupOutcome::AlreadyClean)
        }
    }
}

/// In-memory agent sink used as a contract-compatible remote/platform adapter.
#[derive(Clone, Default)]
pub struct FakeAgentCertificateSink {
    state: Arc<Mutex<HashMap<String, AgentTargetState>>>,
}

#[derive(Debug, Clone, Default)]
struct AgentTargetState {
    active: Option<String>,
    staged: HashMap<String, String>,
    resource_version: u64,
}

impl FakeAgentCertificateSink {
    /// Creates an empty fake agent sink.
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Debug for FakeAgentCertificateSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeAgentCertificateSink")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CertificateSink for FakeAgentCertificateSink {
    async fn stage(
        &self,
        spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: CertificateMaterialRef<'_>,
    ) -> Result<StagedDeployment> {
        if spec.kind != DeliveryTargetKind::Webhook {
            return Err(AcmeError::invalid_input(
                "fake agent sink requires webhook target",
            ));
        }
        let mut states = self.state.lock().expect("agent sink lock poisoned");
        let state = states.entry(spec.reference.clone()).or_default();
        state.resource_version += 1;
        let staged_ref = format!("agent://{}/versions/{}", spec.reference, version.id);
        state
            .staged
            .insert(staged_ref.clone(), material.material.leaf_sha256.clone());
        Ok(StagedDeployment {
            kind: spec.kind,
            target_id: spec.target_id.clone(),
            version_id: version.id.clone(),
            staged_ref,
            previous_active_ref: state.active.clone(),
            leaf_sha256: material.material.leaf_sha256.clone(),
            resource_version: state.resource_version,
        })
    }

    async fn activate(&self, staged: &StagedDeployment) -> Result<()> {
        let mut states = self.state.lock().expect("agent sink lock poisoned");
        let (_, reference) = parse_agent_ref(&staged.staged_ref)?;
        let state = states
            .get_mut(reference)
            .ok_or_else(|| AcmeError::not_found("agent target not staged"))?;
        if state.resource_version != staged.resource_version {
            return Err(AcmeError::conflict("agent resource version changed"));
        }
        if !state.staged.contains_key(&staged.staged_ref) {
            return Err(AcmeError::not_found("staged agent version not found"));
        }
        state.resource_version += 1;
        state.active = Some(staged.staged_ref.clone());
        Ok(())
    }

    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth> {
        let states = self.state.lock().expect("agent sink lock poisoned");
        let (_, reference) = parse_agent_ref(&staged.staged_ref)?;
        let Some(state) = states.get(reference) else {
            return Ok(DeploymentHealth::Unknown("agent target missing".into()));
        };
        if state.active.as_deref() != Some(staged.staged_ref.as_str()) {
            return Ok(DeploymentHealth::Unhealthy(
                "agent active pointer mismatch".into(),
            ));
        }
        if state.staged.get(&staged.staged_ref) == Some(&staged.leaf_sha256) {
            Ok(DeploymentHealth::Healthy)
        } else {
            Ok(DeploymentHealth::Unhealthy(
                "agent fingerprint mismatch".into(),
            ))
        }
    }

    async fn rollback(&self, staged: &StagedDeployment) -> Result<()> {
        let mut states = self.state.lock().expect("agent sink lock poisoned");
        let (_, reference) = parse_agent_ref(&staged.staged_ref)?;
        let state = states
            .get_mut(reference)
            .ok_or_else(|| AcmeError::not_found("agent target missing"))?;
        state.resource_version += 1;
        state.active = staged.previous_active_ref.clone();
        Ok(())
    }

    async fn cleanup(&self, staged: &StagedDeployment) -> Result<CleanupOutcome> {
        let mut states = self.state.lock().expect("agent sink lock poisoned");
        let (_, reference) = parse_agent_ref(&staged.staged_ref)?;
        let Some(state) = states.get_mut(reference) else {
            return Ok(CleanupOutcome::AlreadyClean);
        };
        if state.staged.remove(&staged.staged_ref).is_some() {
            Ok(CleanupOutcome::Cleaned)
        } else {
            Ok(CleanupOutcome::AlreadyClean)
        }
    }
}

fn verify_key_matches_certificate(private_key_pem: &[u8], cert_der: &[u8]) -> Result<()> {
    let pem = std::str::from_utf8(private_key_pem)
        .map_err(|err| AcmeError::crypto(format!("private key is not UTF-8 PEM: {err}")))?;
    let key = rcgen::KeyPair::from_pem(pem)
        .map_err(|err| AcmeError::crypto(format!("parse private key: {err}")))?;
    let public_pem = key.public_key_pem();
    let public = ::pem::parse(public_pem.as_bytes())
        .map_err(|err| AcmeError::pem(format!("parse public key PEM: {err}")))?;
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|err| AcmeError::certificate(format!("parse leaf certificate: {err}")))?;
    if cert.tbs_certificate.subject_pki.raw != public.contents() {
        return Err(AcmeError::crypto(
            "private key does not match certificate public key",
        ));
    }
    Ok(())
}

async fn write_material_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    fs::write(path, bytes).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
    }
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

async fn current_target(root: &Path) -> Result<Option<String>> {
    let current = root.join("current");
    #[cfg(unix)]
    {
        match fs::read_link(&current).await {
            Ok(path) => Ok(Some(path.to_string_lossy().into_owned())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
    #[cfg(not(unix))]
    {
        match fs::read_to_string(&current).await {
            Ok(value) => Ok(Some(value)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}

async fn set_current(root: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(root).await?;
    let tmp = root.join(format!(".current-{}.tmp", std::process::id()));
    if tmp.exists() {
        remove_path(&tmp).await?;
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, &tmp)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp, target.to_string_lossy().as_bytes()).await?;
    }
    fs::rename(&tmp, root.join("current")).await?;
    sync_dir(root)?;
    Ok(())
}

async fn remove_current(root: &Path) -> Result<()> {
    let current = root.join("current");
    if current.exists() {
        remove_path(&current).await?;
    }
    Ok(())
}

async fn remove_path(path: &Path) -> Result<()> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn parse_agent_ref(staged_ref: &str) -> Result<(&str, &str)> {
    let rest = staged_ref
        .strip_prefix("agent://")
        .ok_or_else(|| AcmeError::invalid_input("invalid agent staged reference"))?;
    let (reference, version) = rest
        .split_once("/versions/")
        .ok_or_else(|| AcmeError::invalid_input("invalid agent staged reference"))?;
    Ok((version, reference))
}

fn sink_key(kind: DeliveryTargetKind) -> &'static str {
    match kind {
        DeliveryTargetKind::File => "file",
        DeliveryTargetKind::KubernetesSecret => "kubernetes_secret",
        DeliveryTargetKind::VaultKv => "vault_kv",
        DeliveryTargetKind::Webhook => "webhook",
    }
}

fn deployment_id_for(version_id: &VersionId, target_id: &TargetId) -> Result<DeploymentId> {
    DeploymentId::new(format!(
        "dep_{}_{}",
        version_id.as_str(),
        target_id.as_str()
    ))
}

fn deploy_operation_id_for(version_id: &VersionId, target_id: &TargetId) -> Result<OperationId> {
    OperationId::new(format!(
        "op_deploy_{}_{}",
        version_id.as_str(),
        target_id.as_str()
    ))
}

fn decode_staged(record: &DeploymentRecord) -> Result<StagedDeployment> {
    let staged_ref = record
        .staged_ref
        .as_ref()
        .ok_or_else(|| AcmeError::storage("deployment is missing staged reference"))?;
    serde_json::from_str(staged_ref)
        .map_err(|err| AcmeError::storage(format!("decode staged deployment: {err}")))
}

fn hash_json(value: &serde_json::Value) -> String {
    sha256_hex(value.to_string().as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
