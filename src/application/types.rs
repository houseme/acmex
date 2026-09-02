use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::challenge::ChallengeSession;
use crate::domain::{
    CaPolicy, CertificateIntent, CertificateLineage, CertificateVersion, ChallengeLease,
    ChallengeLeaseId, ChallengeLeaseLocator, IntentId, LineageId, OperationId, OperationRef,
    OperationStatus, OperationSubject, RenewalPolicy, TargetId, TenantId, ValidationPolicy,
    VersionId,
};
use crate::error::Result;
use crate::repository::Versioned;

/// Fine-grained permission required by management API and application commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    IntentRead,
    IntentWrite,
    Issue,
    Renew,
    Revoke,
    Deploy,
    KeyExport,
    Admin,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntentRead => "intent.read",
            Self::IntentWrite => "intent.write",
            Self::Issue => "issue",
            Self::Renew => "renew",
            Self::Revoke => "revoke",
            Self::Deploy => "deploy",
            Self::KeyExport => "key.export",
            Self::Admin => "admin",
        }
    }

    pub fn admin_set() -> Vec<Self> {
        vec![Self::Admin]
    }
}

/// Authenticated caller context after the transport layer has checked access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorContext {
    /// Tenant whose resources are being accessed.
    pub tenant_id: TenantId,
    /// Stable subject identifier for audit/outbox events.
    pub subject: String,
    /// Backward-compatible actor alias.
    pub actor: String,
    /// Caller roles, intentionally low cardinality.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Caller permissions after authorization expansion.
    #[serde(default)]
    pub permissions: Vec<Permission>,
    /// Transport request id for audit/trace correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Source IP or agent summary, controlled by privacy policy at transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl Default for ActorContext {
    fn default() -> Self {
        Self {
            tenant_id: TenantId::default_tenant(),
            subject: "system".to_string(),
            actor: "system".to_string(),
            roles: vec!["system".to_string()],
            permissions: Permission::admin_set(),
            request_id: None,
            source: None,
        }
    }
}

impl ActorContext {
    /// Creates a context from a verified transport principal.
    pub fn new(
        tenant_id: TenantId,
        subject: impl Into<String>,
        roles: Vec<String>,
        permissions: Vec<Permission>,
        request_id: Option<String>,
        source: Option<String>,
    ) -> Self {
        let subject = subject.into();
        Self {
            tenant_id,
            actor: subject.clone(),
            subject,
            roles,
            permissions,
            request_id,
            source,
        }
    }

    pub fn has_permission(&self, required: Permission) -> bool {
        self.permissions.contains(&Permission::Admin) || self.permissions.contains(&required)
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

/// Patch the mutable policy fields of an existing certificate intent.
///
/// Semantics (T08 residual closure):
///
/// * only [`RenewalPolicy`] and `delivery_targets` are mutable; each
///   provided field fully replaces the stored value, omitted fields keep
///   their current value;
/// * `identifiers`, `ca_policy`, `validation_policy` and `key_policy` are
///   immutable — a certificate's SAN set and issuance policy cannot change
///   in place (that is what new intents are for); transport layers reject
///   attempts naming them;
/// * optimistic concurrency: when `expected_generation` is set (carried as
///   an HTTP `If-Match` header) and no longer equals the stored
///   generation, the update fails with a conflict. Without it the patch
///   applies unconditionally (last-write-wins);
/// * every effective mutation bumps the intent `generation` by one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateCertificateIntent {
    /// Caller context.
    pub context: ActorContext,
    /// Intent to patch.
    pub intent_id: IntentId,
    /// Full replacement of the renewal policy; `None` keeps the current one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_policy: Option<RenewalPolicy>,
    /// Full replacement of the delivery target list; `None` keeps the
    /// current list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_targets: Option<Vec<crate::domain::DeliveryTarget>>,
    /// Expected current generation (`If-Match`); mismatch is a conflict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<u64>,
    /// Caller-provided idempotency key. Validated for presence; v1 keeps no
    /// per-intent idempotency ledger, so replay safety comes from the
    /// value-comparison no-op documented on the application service.
    pub idempotency_key: String,
}

impl
    From<(
        ActorContext,
        IntentId,
        Option<RenewalPolicy>,
        Option<Vec<crate::domain::DeliveryTarget>>,
        Option<u64>,
        String,
    )> for UpdateCertificateIntent
{
    /// Builds the command from its positional fields (same order as the
    /// struct).
    ///
    /// Transport layers construct the command through this conversion
    /// instead of naming the type: the application module's public
    /// re-export surface is frozen while intent patching lands, the same
    /// rationale behind [`CertificateApplication::retry_challenge_cleanup`]
    /// taking direct parameters.
    fn from(
        (
            context,
            intent_id,
            renewal_policy,
            delivery_targets,
            expected_generation,
            idempotency_key,
        ): (
            ActorContext,
            IntentId,
            Option<RenewalPolicy>,
            Option<Vec<crate::domain::DeliveryTarget>>,
            Option<u64>,
            String,
        ),
    ) -> Self {
        Self {
            context,
            intent_id,
            renewal_policy,
            delivery_targets,
            expected_generation,
            idempotency_key,
        }
    }
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

/// Token-safe challenge session projection (T05: the API may expose
/// challenge state but must never leak token or key authorization
/// material).
///
/// `token_hash`, the raw token and the key authorization are deliberately
/// absent: nothing an operator needs to inspect lifecycle progress requires
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeSessionView {
    pub id: String,
    pub operation_id: OperationId,
    pub authorization_url: String,
    pub identifier: String,
    pub challenge_type: String,
    pub state: String,
    pub deadline: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl From<ChallengeSession> for ChallengeSessionView {
    fn from(session: ChallengeSession) -> Self {
        Self {
            id: session.id,
            operation_id: session.operation_id,
            authorization_url: session.authorization_url,
            // Canonical ACME wire value ("example.com", "192.0.2.1").
            identifier: session.identifier.acme_value(),
            challenge_type: session.challenge_type.as_str().to_string(),
            state: session.state.as_str().to_string(),
            deadline: session.deadline,
            last_error: session.last_error,
        }
    }
}

/// Redacted challenge lease projection for the cleanup queue.
///
/// The typed locator is collapsed into a human-readable summary that
/// carries no credential material: DNS leases show zone + record name,
/// HTTP/TLS leases show agent + route ids. Locator hashes (DNS
/// `value_hash`, HTTP `token_hash`) are one-way and therefore safe, but
/// are still left out of the summary to keep it short.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeLeaseView {
    pub id: ChallengeLeaseId,
    pub operation_id: OperationId,
    pub challenge_type: String,
    pub locator_summary: String,
    pub cleanup_attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_cleanup_error: Option<String>,
    pub state: String,
}

impl ChallengeLeaseView {
    /// Operator-safe locator summary (see the struct documentation).
    fn summarize_locator(locator: &ChallengeLeaseLocator) -> String {
        match locator {
            ChallengeLeaseLocator::Dns {
                zone, record_name, ..
            } => format!("dns zone={zone} record={record_name}"),
            ChallengeLeaseLocator::Http {
                agent_id, route_id, ..
            } => format!("http agent={agent_id} route={route_id}"),
            ChallengeLeaseLocator::Tls {
                agent_id, route_id, ..
            } => format!("tls agent={agent_id} route={route_id}"),
        }
    }
}

impl From<ChallengeLease> for ChallengeLeaseView {
    fn from(lease: ChallengeLease) -> Self {
        Self {
            id: lease.id,
            operation_id: lease.operation_id,
            challenge_type: lease.challenge_type.as_str().to_string(),
            locator_summary: Self::summarize_locator(&lease.locator),
            cleanup_attempts: lease.cleanup_attempts,
            last_cleanup_error: lease.last_cleanup_error,
            state: lease.state.as_str().to_string(),
        }
    }
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
            state: version.state.as_str().to_string(),
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
    /// Patches the mutable policy fields of an existing intent and returns
    /// the updated view. See [`UpdateCertificateIntent`] for the field
    /// semantics (mutable set, full replacement, generation bump).
    ///
    /// Repeated identical patches are idempotent: when every provided field
    /// compares equal to the stored value the current view is returned
    /// without bumping the generation (v1 has no persisted idempotency
    /// ledger for intent patches, unlike operations).
    ///
    /// Default: adapters that do not implement intent patching report a
    /// configuration error instead of failing silently.
    async fn update_intent(&self, command: UpdateCertificateIntent) -> Result<IntentView> {
        let _ = command;
        Err(crate::error::AcmeError::configuration(
            "intent patch is not implemented by this application service",
        ))
    }
    async fn issue(&self, command: IssueCertificate) -> Result<OperationRef>;
    async fn renew(&self, command: RenewCertificate) -> Result<OperationRef>;
    async fn revoke(&self, command: RevokeCertificate) -> Result<OperationRef>;
    async fn deploy(&self, command: DeployCertificate) -> Result<OperationRef>;
    async fn cancel_operation(&self, command: CancelOperation) -> Result<OperationView>;
    /// Manually requeues a `cleanup_failed` challenge lease (T05 operator
    /// retry entry). The parameters are passed directly instead of a
    /// command struct so transport layers can call it without naming new
    /// application types.
    ///
    /// Default: adapters that do not implement challenge cleanup report a
    /// configuration error instead of failing silently.
    async fn retry_challenge_cleanup(
        &self,
        context: ActorContext,
        lease_id: ChallengeLeaseId,
    ) -> Result<ChallengeLeaseView> {
        let _ = (context, lease_id);
        Err(crate::error::AcmeError::configuration(
            "challenge cleanup retry is not implemented by this application service",
        ))
    }
}

/// Read-only projections.
#[async_trait]
pub trait CertificateQuery: Send + Sync {
    async fn get_intent(&self, id: &IntentId) -> Result<Option<IntentView>>;
    /// Lists intents, newest page first, capped at `limit` (pagination for
    /// large deployments).
    async fn list_intents(&self, limit: usize) -> Result<Vec<IntentView>>;
    async fn get_operation(&self, id: &OperationId) -> Result<Option<OperationView>>;
    async fn list_operations(&self, limit: usize) -> Result<Vec<OperationView>>;
    async fn get_lineage(&self, id: &LineageId) -> Result<Option<CertificateLineage>>;
    async fn list_versions(&self, lineage_id: &LineageId) -> Result<Vec<VersionView>>;
    async fn get_version(&self, id: &VersionId) -> Result<Option<VersionView>>;
    /// Lists the token-safe challenge sessions of one operation. Sessions
    /// carry only `operation_id` (no tenant of their own): for v1 the API
    /// scopes reads by operation and relies on the operation's tenant via
    /// its subject lineage, the same addressing used by operation queries.
    async fn list_challenge_sessions(
        &self,
        operation_id: &OperationId,
    ) -> Result<Vec<ChallengeSessionView>>;
    /// Lists leases still requiring cleanup attention, including
    /// `cleanup_failed` ones awaiting the manual retry entry.
    async fn list_cleanup_pending(&self) -> Result<Vec<ChallengeLeaseView>>;
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
