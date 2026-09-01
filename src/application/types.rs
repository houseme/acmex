use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::domain::{
    CaPolicy, CertificateIntent, CertificateLineage, CertificateVersion, IntentId, LineageId,
    OperationId, OperationRef, OperationStatus, OperationSubject, RenewalPolicy, TargetId,
    TenantId, ValidationPolicy, VersionId,
};
use crate::error::Result;
use crate::repository::Versioned;

/// Authenticated caller context after the transport layer has checked access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorContext {
    /// Tenant whose resources are being accessed.
    pub tenant_id: TenantId,
    /// Stable actor identifier for audit/outbox events.
    pub actor: String,
}

impl Default for ActorContext {
    fn default() -> Self {
        Self {
            tenant_id: TenantId::default_tenant(),
            actor: "system".to_string(),
        }
    }
}

/// Create or return an idempotent certificate intent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateCertificateIntent {
    /// Caller context.
    pub context: ActorContext,
    /// DNS names or IP literals, normalized by the domain model.
    pub identifiers: Vec<String>,
    /// CA/profile policy.
    #[serde(default)]
    pub ca_policy: CaPolicy,
    /// Validation policy.
    #[serde(default)]
    pub validation_policy: ValidationPolicy,
    /// Key lifecycle policy.
    #[serde(default)]
    pub key_policy: crate::domain::KeyPolicy,
    /// Renewal policy.
    #[serde(default)]
    pub renewal_policy: RenewalPolicy,
    /// Delivery targets.
    #[serde(default)]
    pub delivery_targets: Vec<crate::domain::DeliveryTarget>,
    /// Caller-provided idempotency key.
    pub idempotency_key: String,
}

/// Create an issuance operation for an intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueCertificate {
    /// Caller context.
    pub context: ActorContext,
    /// Intent to issue.
    pub intent_id: IntentId,
    /// Caller-provided idempotency key.
    pub idempotency_key: String,
}

/// Create a renewal operation for an existing lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewCertificate {
    /// Caller context.
    pub context: ActorContext,
    /// Existing lineage to renew. API callers should use this stable id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineage_id: Option<LineageId>,
    /// Compatibility selector used by old CLI/domain-based callers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<String>,
    /// Bypass renewal-window checks. T09 records the rate-risk audit detail.
    #[serde(default)]
    pub force: bool,
    /// Caller-provided idempotency key.
    pub idempotency_key: String,
}

/// Create a revocation operation for a certificate version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeCertificate {
    /// Caller context.
    pub context: ActorContext,
    /// Version to revoke.
    pub version_id: VersionId,
    /// Optional ACME revocation reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Caller-provided idempotency key.
    pub idempotency_key: String,
}

/// Create a deployment operation for a certificate version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployCertificate {
    /// Caller context.
    pub context: ActorContext,
    /// Version to deploy.
    pub version_id: VersionId,
    /// Optional target subset. Empty means all targets configured on intent.
    #[serde(default)]
    pub target_ids: Vec<TargetId>,
    /// Caller-provided idempotency key.
    pub idempotency_key: String,
}

/// Request asynchronous operation cancellation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelOperation {
    /// Caller context.
    pub context: ActorContext,
    /// Operation to cancel.
    pub operation_id: OperationId,
}

/// Intent resource projection returned by API/CLI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntentView {
    pub id: IntentId,
    pub tenant_id: TenantId,
    pub identifiers: Vec<String>,
    pub generation: u64,
    pub created_at: Option<Timestamp>,
    pub updated_at: Option<Timestamp>,
}

impl IntentView {
    pub(crate) fn from_intent(intent: &CertificateIntent) -> Self {
        Self {
            id: intent.id.clone(),
            tenant_id: intent.tenant_id.clone(),
            identifiers: intent.identifiers.iter().map(ToString::to_string).collect(),
            generation: intent.generation,
            created_at: None,
            updated_at: None,
        }
    }
}

impl From<Versioned<CertificateIntent>> for IntentView {
    fn from(stored: Versioned<CertificateIntent>) -> Self {
        let mut view = Self::from_intent(&stored.value);
        view.created_at = Some(stored.created_at);
        view.updated_at = Some(stored.updated_at);
        view
    }
}

/// Certificate version projection that never exposes private key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionView {
    pub id: VersionId,
    pub lineage_id: LineageId,
    pub identifiers: Vec<String>,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub issued_by: String,
    pub state: String,
    pub key_provider: String,
    pub key_id: String,
}

impl From<CertificateVersion> for VersionView {
    fn from(version: CertificateVersion) -> Self {
        Self {
            id: version.id,
            lineage_id: version.lineage_id,
            identifiers: version
                .identifiers
                .iter()
                .map(ToString::to_string)
                .collect(),
            serial: version.serial,
            not_before: version.not_before,
            not_after: version.not_after,
            issued_by: version.issued_by,
            state: serde_json::to_value(version.state)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "unknown".to_string()),
            key_provider: version.key_ref.provider,
            key_id: version.key_ref.key_id.to_string(),
        }
    }
}

/// Stable operation projection for polling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationView {
    pub id: OperationId,
    pub kind: String,
    pub status: String,
    pub current_step: Option<String>,
    pub progress: f32,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub retry_at: Option<Timestamp>,
    pub cancel_allowed: bool,
    pub subject: OperationSubject,
    pub error_code: Option<String>,
}

impl From<crate::domain::OperationRecord> for OperationView {
    fn from(record: crate::domain::OperationRecord) -> Self {
        let completed = record
            .steps
            .iter()
            .filter(|s| s.status == crate::domain::StepStatus::Completed)
            .count();
        let progress = if record.steps.is_empty() {
            0.0
        } else {
            completed as f32 / record.steps.len() as f32
        };
        let finished_at = record.status.is_terminal().then_some(record.updated_at);
        let current_step = record.current_step().map(|s| s.kind.as_str().to_string());
        let error_code = record.error.as_ref().map(|e| e.code.as_str().to_string());
        Self {
            id: record.id,
            kind: record.kind.as_str().to_string(),
            status: record.status.as_str().to_string(),
            current_step,
            progress,
            created_at: record.created_at,
            updated_at: record.updated_at,
            finished_at,
            retry_at: record.wake_at,
            cancel_allowed: !record.status.is_terminal()
                && record.status != OperationStatus::CancelRequested,
            subject: record.subject,
            error_code,
        }
    }
}

/// Mutating use cases.
#[async_trait]
pub trait CertificateApplication: Send + Sync {
    async fn create_intent(&self, command: CreateCertificateIntent) -> Result<IntentView>;
    async fn issue(&self, command: IssueCertificate) -> Result<OperationRef>;
    async fn renew(&self, command: RenewCertificate) -> Result<OperationRef>;
    async fn revoke(&self, command: RevokeCertificate) -> Result<OperationRef>;
    async fn deploy(&self, command: DeployCertificate) -> Result<OperationRef>;
    async fn cancel_operation(&self, command: CancelOperation) -> Result<OperationView>;
}

/// Read-only projections.
#[async_trait]
pub trait CertificateQuery: Send + Sync {
    async fn get_intent(&self, id: &IntentId) -> Result<Option<IntentView>>;
    async fn list_intents(&self) -> Result<Vec<IntentView>>;
    async fn get_operation(&self, id: &OperationId) -> Result<Option<OperationView>>;
    async fn list_operations(&self, limit: usize) -> Result<Vec<OperationView>>;
    async fn get_lineage(&self, id: &LineageId) -> Result<Option<CertificateLineage>>;
    async fn list_versions(&self, lineage_id: &LineageId) -> Result<Vec<VersionView>>;
    async fn get_version(&self, id: &VersionId) -> Result<Option<VersionView>>;
}

pub(crate) fn command_hash<T: Serialize>(value: &T) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

pub(crate) fn ensure_idempotency_key(key: &str) -> Result<String> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err(crate::error::AcmeError::invalid_input(
            "Idempotency-Key is required for mutating certificate requests",
        ));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn op_ref(record: &crate::domain::OperationRecord) -> OperationRef {
    OperationRef {
        id: record.id.clone(),
        kind: record.kind,
        subject: record.subject.clone(),
    }
}
