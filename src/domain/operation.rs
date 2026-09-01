//! Durable operation model: identity, state machine, workflow steps and
//! error classification.
//!
//! An operation is the persisted representation of any long-running
//! lifecycle action (issue/renew/revoke/deploy/challenge-cleanup). It owns
//! a linear list of [`WorkflowStepKind`]s whose per-attempt state is
//! persisted after every transition (see the workflow engine, roadmap T03),
//! together with a stable error classification so callers can decide
//! between retry, operator action or terminal failure without string
//! matching.

use serde::{Deserialize, Serialize};

use jiff::Timestamp;

use super::ids::{IntentId, LineageId, OperationId, VersionId};

/// What an operation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Initial certificate issuance for an intent.
    Issue,
    /// Renewal of an existing lineage.
    Renew,
    /// Revocation of a certificate version.
    Revoke,
    /// Deployment of a certificate version to delivery targets.
    Deploy,
    /// Cleanup of challenge resources left behind by another operation.
    ChallengeCleanup,
}

impl OperationKind {
    /// Stable wire name (API-facing, never the Rust debug form).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Renew => "renew",
            Self::Revoke => "revoke",
            Self::Deploy => "deploy",
            Self::ChallengeCleanup => "challenge_cleanup",
        }
    }
}

/// Lifecycle state of an operation.
///
/// State transitions are validated by [`OperationRecord::transition`];
/// serde values are stable strings used verbatim by the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    /// Created, not yet picked up by a worker.
    Queued,
    /// A worker is executing the current step.
    Running,
    /// Blocked on an external event; `wake_at` decides resumption.
    Waiting,
    /// Finished successfully.
    Succeeded,
    /// Terminally failed.
    Failed,
    /// Cancellation was requested; the worker will observe it.
    CancelRequested,
    /// Cancellation finished (including compensation).
    Cancelled,
    /// Running compensating (cleanup) actions after failure/cancel.
    Compensating,
    /// Compensation failed and requires operator attention.
    CompensationFailed,
}

impl OperationStatus {
    /// Stable wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::CancelRequested => "cancel_requested",
            Self::Cancelled => "cancelled",
            Self::Compensating => "compensating",
            Self::CompensationFailed => "compensation_failed",
        }
    }

    /// Terminal states never transition again.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::CompensationFailed
        )
    }
}

/// The linear steps of the initial issuance workflow.
///
/// Renewals reuse the same spine (roadmap T09 adds `replaces` handling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStepKind {
    /// Policy validation and validation planning (pure).
    Plan,
    /// Ensure a reusable CA account exists.
    EnsureAccount,
    /// Create an ACME order or resume a previously persisted one.
    CreateOrResumeOrder,
    /// Fetch all authorization objects for the order.
    LoadAuthorizations,
    /// Create external validation resources (DNS record, HTTP route...).
    PrepareChallenges,
    /// Observe external propagation until quorum.
    WaitPropagation,
    /// Tell the CA to start validating (challenge respond).
    AcknowledgeChallenges,
    /// Poll authorizations until valid/invalid.
    WaitAuthorizations,
    /// Create/obtain the CSR via the KeyProvider.
    CreateCsr,
    /// Submit the CSR to the CA (finalize).
    FinalizeOrder,
    /// Poll the order until valid.
    WaitOrder,
    /// Download the issued certificate chain.
    DownloadCertificate,
    /// Strictly verify the issued certificate against the intent.
    VerifyCertificate,
    /// Persist the immutable certificate version.
    PersistVersion,
    /// Create deployment child operations for delivery targets.
    ScheduleDeployments,
    /// Stage certificate material into a deployment target.
    StageDeployment,
    /// Activate staged certificate material at a deployment target.
    ActivateDeployment,
    /// Verify a deployment target serves the expected version.
    VerifyDeployment,
    /// Roll back a partially activated deployment target.
    RollbackDeployment,
    /// Clean up challenge resources.
    CleanupChallenges,
    /// Final bookkeeping.
    Complete,
}

impl WorkflowStepKind {
    /// Stable wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::EnsureAccount => "ensure_account",
            Self::CreateOrResumeOrder => "create_or_resume_order",
            Self::LoadAuthorizations => "load_authorizations",
            Self::PrepareChallenges => "prepare_challenges",
            Self::WaitPropagation => "wait_propagation",
            Self::AcknowledgeChallenges => "acknowledge_challenges",
            Self::WaitAuthorizations => "wait_authorizations",
            Self::CreateCsr => "create_csr",
            Self::FinalizeOrder => "finalize_order",
            Self::WaitOrder => "wait_order",
            Self::DownloadCertificate => "download_certificate",
            Self::VerifyCertificate => "verify_certificate",
            Self::PersistVersion => "persist_version",
            Self::ScheduleDeployments => "schedule_deployments",
            Self::StageDeployment => "stage_deployment",
            Self::ActivateDeployment => "activate_deployment",
            Self::VerifyDeployment => "verify_deployment",
            Self::RollbackDeployment => "rollback_deployment",
            Self::CleanupChallenges => "cleanup_challenges",
            Self::Complete => "complete",
        }
    }

    /// The default issuance step sequence.
    pub fn issuance_spine() -> &'static [WorkflowStepKind] {
        use WorkflowStepKind::*;
        &[
            Plan,
            EnsureAccount,
            CreateOrResumeOrder,
            LoadAuthorizations,
            PrepareChallenges,
            WaitPropagation,
            AcknowledgeChallenges,
            WaitAuthorizations,
            CreateCsr,
            FinalizeOrder,
            WaitOrder,
            DownloadCertificate,
            VerifyCertificate,
            PersistVersion,
            ScheduleDeployments,
            CleanupChallenges,
            Complete,
        ]
    }
}

/// Status of one step attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// Not started.
    Pending,
    /// Currently executing (crash-recovery marker).
    Running,
    /// Completed successfully.
    Completed,
    /// Failed (retry decision encoded on the operation).
    Failed,
}

/// Compensation (cleanup) state of a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompensationState {
    /// No compensation required.
    #[default]
    NotRequired,
    /// Compensation will run when the operation ends.
    Pending,
    /// Compensation succeeded.
    Done,
    /// Compensation failed; retried independently.
    Failed,
}

/// Persisted per-step record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecord {
    /// Which step this is.
    pub kind: WorkflowStepKind,
    /// 1-based attempt counter.
    pub attempt: u32,
    /// Current status.
    pub status: StepStatus,
    /// When the current attempt started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<Timestamp>,
    /// When the current attempt finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<Timestamp>,
    /// Locator of the external side effect created by this step (order URL,
    /// DNS record id, route id...), persisted as soon as it exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side_effect_locator: Option<String>,
    /// Serialized step output reference (repository key or URL), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_ref: Option<String>,
    /// Last error, classified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ClassifiedError>,
    /// Compensation state.
    #[serde(default)]
    pub compensation: CompensationState,
    /// Compensation attempt counter.
    #[serde(default)]
    pub compensation_attempts: u32,
}

impl StepRecord {
    /// A fresh pending record for a step kind.
    pub fn pending(kind: WorkflowStepKind) -> Self {
        Self {
            kind,
            attempt: 0,
            status: StepStatus::Pending,
            started_at: None,
            finished_at: None,
            side_effect_locator: None,
            output_ref: None,
            error: None,
            compensation: CompensationState::NotRequired,
            compensation_attempts: 0,
        }
    }
}

/// Stable machine-readable error code (e.g. `ACME_BAD_NONCE_EXHAUSTED`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StableErrorCode(std::borrow::Cow<'static, str>);

impl StableErrorCode {
    /// Creates a code from a static string (const-constructible).
    pub const fn new(code: &'static str) -> Self {
        Self(std::borrow::Cow::Borrowed(code))
    }

    /// Creates a code from an owned string.
    pub fn from_owned(code: String) -> Self {
        Self(std::borrow::Cow::Owned(code))
    }

    /// The code text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for StableErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Well-known stable error codes used across the workflow engine.
pub mod error_codes {
    use super::StableErrorCode as Code;

    /// CA kept returning badNonce beyond the internal retry budget.
    pub const ACME_BAD_NONCE_EXHAUSTED: Code = Code::new("ACME_BAD_NONCE_EXHAUSTED");
    /// The CA (or an upstream) rate limited the request.
    pub const ACME_RATE_LIMITED: Code = Code::new("ACME_RATE_LIMITED");
    /// Temporary CA-side server error.
    pub const ACME_SERVER_ERROR: Code = Code::new("ACME_SERVER_ERROR");
    /// The requested identifiers/challenges violate policy.
    pub const VALIDATION_CHALLENGE_INCOMPATIBLE: Code =
        Code::new("VALIDATION_CHALLENGE_INCOMPATIBLE");
    /// Propagation observation timed out.
    pub const CHALLENGE_PROPAGATION_TIMEOUT: Code = Code::new("CHALLENGE_PROPAGATION_TIMEOUT");
    /// Cleaning up challenge resources failed.
    pub const CHALLENGE_CLEANUP_FAILED: Code = Code::new("CHALLENGE_CLEANUP_FAILED");
    /// Provider rejected the credentials.
    pub const PROVIDER_AUTH_FAILED: Code = Code::new("PROVIDER_AUTH_FAILED");
    /// Optimistic-concurrency conflict (should re-read and retry).
    pub const REPOSITORY_CAS_CONFLICT: Code = Code::new("REPOSITORY_CAS_CONFLICT");
    /// Unclassified internal error.
    pub const INTERNAL: Code = Code::new("INTERNAL");
}

/// How a failure should be handled by the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "class")]
pub enum ErrorClass {
    /// Transient; retry with backoff.
    Retryable,
    /// Rate limited; honor `retry_after` when present.
    RateLimited {
        /// Server-provided instant after which retry is allowed.
        #[serde(skip_serializing_if = "Option::is_none")]
        retry_after: Option<Timestamp>,
    },
    /// Permanent; no retry will ever succeed.
    Terminal,
    /// The request violates policy (rejected before side effects).
    PolicyViolation,
    /// A human must fix credentials/configuration before retry.
    OperatorActionRequired,
    /// The operation was cancelled.
    Cancelled,
}

impl ErrorClass {
    /// Whether retrying is meaningful at all.
    pub fn retryable(&self) -> bool {
        matches!(self, Self::Retryable | Self::RateLimited { .. })
    }
}

/// A classified error attached to a step or operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedError {
    /// Stable error code.
    pub code: StableErrorCode,
    /// Error class driving retry decisions.
    pub class: ErrorClass,
    /// Human-readable detail; must never contain secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The resources an operation acts on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSubject {
    /// The intent this operation fulfils, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_id: Option<IntentId>,
    /// The lineage this operation is about, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineage_id: Option<LineageId>,
    /// The certificate version this operation is about, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<VersionId>,
}

impl OperationSubject {
    /// An empty subject (filled in as the operation progresses).
    pub fn empty() -> Self {
        Self {
            intent_id: None,
            lineage_id: None,
            version_id: None,
        }
    }

    /// Subject referencing an intent.
    pub fn for_intent(intent_id: IntentId) -> Self {
        Self {
            intent_id: Some(intent_id),
            lineage_id: None,
            version_id: None,
        }
    }
}

/// A durable operation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    /// Unique identity.
    pub id: OperationId,
    /// What the operation does.
    pub kind: OperationKind,
    /// Current lifecycle state.
    pub status: OperationStatus,
    /// Resources this operation acts on.
    pub subject: OperationSubject,
    /// Schema version of the workflow itself.
    pub workflow_version: u32,
    /// The linear step spine with per-step state.
    pub steps: Vec<StepRecord>,
    /// Index of the current step in `steps`.
    pub current_step_index: usize,
    /// When a waiting operation should be resumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wake_at: Option<Timestamp>,
    /// Creation time.
    pub created_at: Timestamp,
    /// Last update time.
    pub updated_at: Timestamp,
    /// Terminal error, when failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ClassifiedError>,
    /// Idempotency key supplied by the caller (dedup across retries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Hash of the canonicalized request (dedup across retries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
}

impl OperationRecord {
    /// Creates a queued operation with the default issuance spine.
    pub fn new_issue(
        id: OperationId,
        subject: OperationSubject,
        idempotency_key: Option<String>,
        request_hash: Option<String>,
        now: Timestamp,
    ) -> Self {
        Self::new(
            id,
            OperationKind::Issue,
            subject,
            idempotency_key,
            request_hash,
            now,
        )
    }

    /// Creates a queued operation with the spine for its kind.
    pub fn new(
        id: OperationId,
        kind: OperationKind,
        subject: OperationSubject,
        idempotency_key: Option<String>,
        request_hash: Option<String>,
        now: Timestamp,
    ) -> Self {
        let spine: &[WorkflowStepKind] = match kind {
            OperationKind::Issue | OperationKind::Renew => WorkflowStepKind::issuance_spine(),
            OperationKind::Revoke => &[
                WorkflowStepKind::Plan,
                WorkflowStepKind::EnsureAccount,
                WorkflowStepKind::Complete,
            ],
            OperationKind::Deploy => &[
                WorkflowStepKind::StageDeployment,
                WorkflowStepKind::ActivateDeployment,
                WorkflowStepKind::VerifyDeployment,
                WorkflowStepKind::Complete,
            ],
            OperationKind::ChallengeCleanup => &[
                WorkflowStepKind::CleanupChallenges,
                WorkflowStepKind::Complete,
            ],
        };
        Self {
            id,
            kind,
            status: OperationStatus::Queued,
            subject,
            workflow_version: 1,
            steps: spine.iter().map(|k| StepRecord::pending(*k)).collect(),
            current_step_index: 0,
            wake_at: None,
            created_at: now,
            updated_at: now,
            error: None,
            idempotency_key,
            request_hash,
        }
    }

    /// Whether the operation is ready to be picked up / resumed.
    ///
    /// Non-terminal operations whose `wake_at` has passed are ready.
    pub fn is_ready_at(&self, now: Timestamp) -> bool {
        if self.status.is_terminal() {
            return false;
        }
        match self.wake_at {
            Some(wake) => now >= wake,
            None => true,
        }
    }

    /// Validates and applies a status transition, returning the new record.
    pub fn transition(&self, next: OperationStatus) -> Result<OperationRecord, String> {
        let legal = matches!(
            (self.status, next),
            (OperationStatus::Queued, OperationStatus::Running)
                | (OperationStatus::Queued, OperationStatus::CancelRequested)
                | (OperationStatus::Running, OperationStatus::Waiting)
                | (OperationStatus::Running, OperationStatus::Running)
                | (OperationStatus::Running, OperationStatus::Succeeded)
                | (OperationStatus::Running, OperationStatus::Failed)
                | (OperationStatus::Running, OperationStatus::CancelRequested)
                | (OperationStatus::Waiting, OperationStatus::Running)
                | (OperationStatus::Waiting, OperationStatus::CancelRequested)
                | (OperationStatus::CancelRequested, OperationStatus::Cancelled)
                | (
                    OperationStatus::CancelRequested,
                    OperationStatus::Compensating
                )
                | (_, OperationStatus::Compensating)
                | (OperationStatus::Compensating, OperationStatus::Cancelled)
                | (
                    OperationStatus::Compensating,
                    OperationStatus::CompensationFailed
                )
                | (OperationStatus::Compensating, OperationStatus::Succeeded)
                | (_, OperationStatus::Failed)
        );
        if !legal {
            return Err(format!(
                "illegal operation transition {:?} -> {:?}",
                self.status, next
            ));
        }
        if self.status.is_terminal() {
            return Err(format!(
                "operation {:?} is terminal and cannot transition to {:?}",
                self.status, next
            ));
        }
        let mut next_record = self.clone();
        next_record.status = next;
        Ok(next_record)
    }

    /// The current step record, if any.
    pub fn current_step(&self) -> Option<&StepRecord> {
        self.steps.get(self.current_step_index)
    }
}

/// A reference to an operation returned by application services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRef {
    /// The operation identity.
    pub id: OperationId,
    /// What kind of operation it is.
    pub kind: OperationKind,
    /// The subject resources.
    pub subject: OperationSubject,
}

impl From<&OperationRecord> for OperationRef {
    fn from(record: &OperationRecord) -> Self {
        Self {
            id: record.id.clone(),
            kind: record.kind,
            subject: record.subject.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        Timestamp::now()
    }

    fn record() -> OperationRecord {
        OperationRecord::new_issue(
            super::super::OperationId::generate(),
            OperationSubject::empty(),
            None,
            None,
            now(),
        )
    }

    #[test]
    fn kind_wire_names_are_stable() {
        assert_eq!(OperationKind::Issue.as_str(), "issue");
        assert_eq!(
            OperationKind::ChallengeCleanup.as_str(),
            "challenge_cleanup"
        );
        assert_eq!(
            serde_json::to_string(&OperationKind::Renew).unwrap(),
            "\"renew\""
        );
    }

    #[test]
    fn status_wire_names_are_stable() {
        assert_eq!(
            OperationStatus::CancelRequested.as_str(),
            "cancel_requested"
        );
        assert_eq!(
            serde_json::to_string(&OperationStatus::CompensationFailed).unwrap(),
            "\"compensation_failed\""
        );
    }

    #[test]
    fn new_issue_has_full_spine() {
        let record = record();
        assert_eq!(record.status, OperationStatus::Queued);
        assert_eq!(record.steps.len(), 17);
        assert_eq!(record.steps[0].kind, WorkflowStepKind::Plan);
        assert_eq!(
            record.steps.last().unwrap().kind,
            WorkflowStepKind::Complete
        );
        assert!(record.is_ready_at(now()));
    }

    #[test]
    fn legal_transitions() {
        let record = record();
        let running = record
            .transition(OperationStatus::Running)
            .expect("queued -> running");
        let waiting = running
            .transition(OperationStatus::Waiting)
            .expect("running -> waiting");
        let resumed = waiting
            .transition(OperationStatus::Running)
            .expect("waiting -> running");
        resumed
            .transition(OperationStatus::Succeeded)
            .expect("running -> succeeded");
    }

    #[test]
    fn illegal_transitions_rejected() {
        let record = record();
        assert!(record.transition(OperationStatus::Succeeded).is_err());
        assert!(record.transition(OperationStatus::Cancelled).is_err());
        let done = record
            .transition(OperationStatus::Running)
            .unwrap()
            .transition(OperationStatus::Succeeded)
            .unwrap();
        assert!(done.transition(OperationStatus::Running).is_err());
        assert!(done.transition(OperationStatus::Failed).is_err());
    }

    #[test]
    fn waiting_not_ready_until_wake_at() {
        let now = now();
        let mut record = record();
        record.status = OperationStatus::Waiting;
        record.wake_at = Some(now.checked_add(jiff::Span::new().seconds(30)).unwrap());
        assert!(!record.is_ready_at(now));
        assert!(record.is_ready_at(now.checked_add(jiff::Span::new().seconds(60)).unwrap()));
    }

    #[test]
    fn error_classes_retryability() {
        assert!(ErrorClass::Retryable.retryable());
        assert!(ErrorClass::RateLimited { retry_after: None }.retryable());
        assert!(!ErrorClass::Terminal.retryable());
        assert!(!ErrorClass::PolicyViolation.retryable());
        assert!(!ErrorClass::OperatorActionRequired.retryable());
        assert!(!ErrorClass::Cancelled.retryable());
    }

    #[test]
    fn operation_json_roundtrip() {
        let record = OperationRecord::new_issue(
            super::super::OperationId::generate(),
            OperationSubject::empty(),
            Some("idem-42".to_string()),
            Some("deadbeef".to_string()),
            now(),
        );
        let json = serde_json::to_string(&record).unwrap();
        let back: OperationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }
}
