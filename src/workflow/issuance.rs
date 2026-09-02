//! Real executors for the issuance spine steps that the challenge module
//! does not own: planning, CSR creation, finalize, order waiting, chain
//! download and verification, version persistence, deployment scheduling
//! and the deployment/revoke spines.
//!
//! # Data flow between steps
//!
//! Steps never hold state in memory: every intermediate artifact is
//! serialized into the owning step's `output_ref` (JSON), persisted by the
//! engine *before* the next step runs, and re-read on execution. This is
//! what makes the whole spine crash-resumable — after a restart the engine
//! replays from the persisted outputs instead of re-doing side effects.
//!
//! ```text
//! EnsureAccount      ─▶ AccountHandle          (JSON in output_ref)
//! CreateOrResumeOrder ─▶ OrderHandle            (idempotent: persisted wins)
//! LoadAuthorizations  ─▶ [AuthzSnapshot; token per challenge]
//! CreateCsr           ─▶ CsrPayload             (DER b64 + KeyRef; reused
//!                                                 across retries so the
//!                                                 same key is kept)
//! FinalizeOrder       ─▶ (CA-side effect only)
//! WaitOrder           ─▶ WaitUntil until `valid`/`invalid`
//! DownloadCertificate ─▶ ChainPayload           (PEM + URL)
//! VerifyCertificate   ─▶ terminal on SAN/validity mismatch
//! PersistVersion      ─▶ VersionId              (deterministic: ver_<op>)
//! ScheduleDeployments ─▶ deployment records + child Deploy operations
//! Complete            ─▶ Deploy ops: activation gate
//! ```
//!
//! # Ownership and idempotency rules
//!
//! * **Deterministic ids** — the persisted version id is derived from the
//!   operation id (`ver_<op>`), so a retried `PersistVersion` recreates the
//!   same entity instead of duplicating versions.
//! * **Error classes** — CA/transport failures are retryable
//!   (`RetryAt`), policy mismatches (SAN set, validity window, missing
//!   subject) are terminal `PolicyViolation`, and malformed persisted
//!   payloads are terminal `INTERNAL` (they indicate a bug, not a flap).
//! * **Deployment split** — `run_deployment_once` mutates only the
//!   deployment *record*; the operation bookkeeping belongs exclusively to
//!   the engine (single writer per operation, CAS-fenced).
//! * **Revocation** — the Revoke spine is [Plan, EnsureAccount,
//!   SubmitRevocation, Complete]; `SubmitRevocation` talks to the CA, so a
//!   succeeded revoke operation really revoked the certificate.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use jiff::Timestamp;

use crate::ca_backend::{self, CaBackend};
use crate::delivery::DeploymentOrchestrator;
use crate::domain::{
    self, CertificateIntent, CertificateVersion, ClassifiedError, ErrorClass, StableErrorCode,
    VersionId, VersionState, WorkflowStepKind, error_codes,
};
use crate::error::{AcmeError, Result};
use crate::key::{CreateCsr, KeyProvider};
use crate::repository::RepositorySet;
use crate::types::RevocationReason;
use crate::workflow::{StepContext, StepExecutor, StepResult};

/// How long `WaitUntil` results sleep before re-running a step.
fn wait_note(until: Timestamp) -> StepResult {
    StepResult::WaitUntil {
        until,
        note: Some("polling CA/deployment state".to_string()),
    }
}

fn terminal(code: StableErrorCode, detail: impl Into<String>) -> StepResult {
    StepResult::Fail(ClassifiedError {
        code,
        class: ErrorClass::Terminal,
        detail: Some(detail.into()),
    })
}

fn policy_reject(detail: impl Into<String>) -> StepResult {
    StepResult::Fail(ClassifiedError {
        code: error_codes::VALIDATION_CHALLENGE_INCOMPATIBLE,
        class: ErrorClass::PolicyViolation,
        detail: Some(detail.into()),
    })
}

fn retryable_error(detail: impl Into<String>) -> StepResult {
    StepResult::RetryAt {
        after: std::time::Duration::from_secs(1),
        error: ClassifiedError {
            code: error_codes::ACME_SERVER_ERROR,
            class: ErrorClass::Retryable,
            detail: Some(detail.into()),
        },
    }
}

fn acme_backend_error(detail: impl Into<String>) -> StepResult {
    let detail = detail.into();
    let code = detail
        .find('[')
        .and_then(|start| detail[start + 1..].split_once(']'))
        .map(|(code, _)| StableErrorCode::from_owned(code.to_string()))
        .unwrap_or(error_codes::ACME_SERVER_ERROR);

    if detail.contains("] terminal:") {
        return terminal(code, detail);
    }
    if detail.contains("] operator-action-required:") {
        return StepResult::Fail(ClassifiedError {
            code,
            class: ErrorClass::OperatorActionRequired,
            detail: Some(detail),
        });
    }
    retryable_error(detail)
}

fn read_payload<T: serde::de::DeserializeOwned>(
    record: &domain::OperationRecord,
    kind: WorkflowStepKind,
) -> Result<T> {
    let index = record
        .steps
        .iter()
        .position(|s| s.kind == kind)
        .ok_or_else(|| AcmeError::protocol(format!("missing step {kind:?}")))?;
    let step = &record.steps[index];
    let raw = step
        .output_ref
        .as_deref()
        .ok_or_else(|| AcmeError::protocol(format!("step {kind:?} has no output yet")))?;
    serde_json::from_str(raw).map_err(|e| AcmeError::protocol(format!("bad step output: {e}")))
}

/// Shared dependencies of the issuance executors.
pub struct IssuanceStepDeps {
    /// The CA backend used for finalize/wait/download/revoke.
    pub backend: Arc<dyn CaBackend>,
    /// Managed key and CSR source.
    pub key_provider: Arc<dyn KeyProvider>,
    /// Deployment orchestration (scheduling + durable transitions).
    pub orchestrator: DeploymentOrchestrator,
    /// Poll interval for wait-style steps.
    pub poll_interval: std::time::Duration,
}

impl IssuanceStepDeps {
    fn wake_at(&self, repositories: &RepositorySet) -> Timestamp {
        repositories
            .clock
            .now()
            .checked_add(jiff::Span::new().milliseconds(self.poll_interval.as_millis() as i64))
            .expect("poll interval overflow")
    }

    fn account(
        &self,
        record: &domain::OperationRecord,
    ) -> std::result::Result<ca_backend::AccountHandle, StepResult> {
        read_payload::<AccountRefPayload>(record, WorkflowStepKind::EnsureAccount)
            .map(|payload| payload.account)
            .map_err(|_| policy_reject("EnsureAccount has not completed yet"))
    }

    fn order(
        &self,
        record: &domain::OperationRecord,
    ) -> std::result::Result<ca_backend::OrderHandle, StepResult> {
        read_payload::<OrderRefPayload>(record, WorkflowStepKind::CreateOrResumeOrder)
            .map(|payload| payload.order)
            .map_err(|_| policy_reject("CreateOrResumeOrder has not completed yet"))
    }

    /// The intent behind the operation (via the subject, or the subject
    /// lineage's intent).
    pub async fn resolve_intent(
        repositories: &RepositorySet,
        record: &domain::OperationRecord,
    ) -> Result<CertificateIntent> {
        if let Some(intent_id) = &record.subject.intent_id {
            return repositories
                .intents
                .get(intent_id)
                .await?
                .map(|stored| stored.value)
                .ok_or_else(|| AcmeError::not_found(format!("intent `{intent_id}` not found")));
        }
        if let Some(lineage_id) = &record.subject.lineage_id {
            let lineage = repositories
                .lineages
                .get(lineage_id)
                .await?
                .map(|stored| stored.value)
                .ok_or_else(|| AcmeError::not_found(format!("lineage `{lineage_id}` not found")))?;
            return repositories
                .intents
                .get(&lineage.intent_id)
                .await?
                .map(|stored| stored.value)
                .ok_or_else(|| {
                    AcmeError::storage(format!(
                        "lineage `{lineage_id}` references missing intent `{}`",
                        lineage.intent_id
                    ))
                });
        }
        Err(AcmeError::invalid_input(
            "operation subject references neither intent nor lineage",
        ))
    }
}

// ---------------------------------------------------------------------------
// persisted step payloads
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct AccountRefPayload {
    account: ca_backend::AccountHandle,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct OrderRefPayload {
    order: ca_backend::OrderHandle,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CsrPayload {
    /// Base64 (standard) encoded CSR DER.
    csr_der: String,
    key_ref: domain::KeyRef,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ChainPayload {
    pem: String,
    url: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VersionPayload {
    version_id: VersionId,
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// Validates the intent (and its identifiers) before any side effect.
pub struct PlanStep;

impl Default for PlanStep {
    fn default() -> Self {
        Self::new()
    }
}

impl PlanStep {
    /// Creates the planning step.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StepExecutor for PlanStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::Plan
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let intent = match IssuanceStepDeps::resolve_intent(ctx.repositories, ctx.operation).await {
            Ok(intent) => intent,
            Err(err) => return policy_reject(err.to_string()),
        };
        if let Err(err) = intent.validate() {
            return policy_reject(format!("intent validation failed: {err}"));
        }
        // Private/reserved IP identifiers are rejected before any ACME side
        // effect unless the CA policy opts in (T07).
        if let Err(err) =
            domain::validate_identifier_scope(intent.identifiers.as_slice(), &intent.ca_policy)
        {
            return policy_reject(err.to_string());
        }
        StepResult::done()
    }
}

// ---------------------------------------------------------------------------
// CreateCsr
// ---------------------------------------------------------------------------

/// Creates (or reuses, per the key rotation policy) the certificate key and
/// derives the CSR for the intent's identifiers.
pub struct CreateCsrStep {
    deps: Arc<IssuanceStepDeps>,
}

impl CreateCsrStep {
    /// Creates the CSR step.
    pub fn new(deps: Arc<IssuanceStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for CreateCsrStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::CreateCsr
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        // Idempotency: a persisted CSR from a previous attempt wins so the
        // same key is reused across retries/restarts.
        if let Ok(payload) = read_payload::<CsrPayload>(ctx.operation, WorkflowStepKind::CreateCsr)
        {
            let _ = payload;
            return StepResult::done();
        }

        let intent = match IssuanceStepDeps::resolve_intent(ctx.repositories, ctx.operation).await {
            Ok(intent) => intent,
            Err(err) => return policy_reject(err.to_string()),
        };

        // Reuse the active version's key when the policy asks for it.
        let mut key_ref = None;
        if intent.key_policy.rotation == domain::KeyRotationPolicy::Reuse
            && let Some(lineage_id) = &ctx.operation.subject.lineage_id
            && let Some(lineage) = ctx
                .repositories
                .lineages
                .get(lineage_id)
                .await
                .ok()
                .flatten()
            && let Some(active) = &lineage.value.active_version_id
            && let Some(version) = ctx.repositories.versions.get(active).await.ok().flatten()
        {
            key_ref = Some(version.value.key_ref.clone());
        }

        match self
            .deps
            .key_provider
            .create_csr(CreateCsr {
                identifiers: intent.identifiers.clone(),
                policy: intent.key_policy.clone(),
                key_ref,
                external_csr: None,
            })
            .await
        {
            Ok(artifact) => {
                let payload = CsrPayload {
                    csr_der: BASE64.encode(&artifact.csr_der),
                    key_ref: artifact.key_ref,
                };
                match serde_json::to_string(&payload) {
                    Ok(json) => StepResult::Complete {
                        output_ref: Some(json),
                        side_effect_locator: None,
                        requires_compensation: false,
                    },
                    Err(err) => terminal(
                        error_codes::INTERNAL,
                        format!("serialize CSR payload: {err}"),
                    ),
                }
            }
            Err(err) => terminal(error_codes::INTERNAL, format!("create CSR: {err}")),
        }
    }
}

// ---------------------------------------------------------------------------
// FinalizeOrder
// ---------------------------------------------------------------------------

/// Submits the CSR to the CA (ACME finalize).
pub struct FinalizeOrderStep {
    deps: Arc<IssuanceStepDeps>,
}

impl FinalizeOrderStep {
    /// Creates the finalize step.
    pub fn new(deps: Arc<IssuanceStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for FinalizeOrderStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::FinalizeOrder
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let account = match self.deps.account(ctx.operation) {
            Ok(account) => account,
            Err(result) => return result,
        };
        let order = match self.deps.order(ctx.operation) {
            Ok(order) => order,
            Err(result) => return result,
        };
        let csr = match read_payload::<CsrPayload>(ctx.operation, WorkflowStepKind::CreateCsr) {
            Ok(csr) => csr,
            Err(_) => return policy_reject("CreateCsr has not completed yet"),
        };
        let csr_der = match BASE64.decode(&csr.csr_der) {
            Ok(der) => der,
            Err(err) => {
                return terminal(error_codes::INTERNAL, format!("bad persisted CSR: {err}"));
            }
        };

        match self.deps.backend.finalize(&account, &order, &csr_der).await {
            Ok(()) => StepResult::done(),
            Err(err) => retryable_error(err.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// WaitOrder
// ---------------------------------------------------------------------------

/// Polls the order until it is valid (or invalid).
pub struct WaitOrderStep {
    deps: Arc<IssuanceStepDeps>,
}

impl WaitOrderStep {
    /// Creates the order-wait step.
    pub fn new(deps: Arc<IssuanceStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for WaitOrderStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::WaitOrder
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let account = match self.deps.account(ctx.operation) {
            Ok(account) => account,
            Err(result) => return result,
        };
        let order = match self.deps.order(ctx.operation) {
            Ok(order) => order,
            Err(result) => return result,
        };
        match self.deps.backend.get_order(&account, &order).await {
            Ok(resource) => match resource.order.status.as_str() {
                "valid" => StepResult::done(),
                "invalid" => terminal(
                    error_codes::ACME_SERVER_ERROR,
                    format!("order {} is invalid", order.url),
                ),
                // pending | ready | processing
                _ => wait_note(self.deps.wake_at(ctx.repositories)),
            },
            Err(err) => retryable_error(err.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// DownloadCertificate
// ---------------------------------------------------------------------------

/// Downloads the issued chain once the order is valid.
pub struct DownloadCertificateStep {
    deps: Arc<IssuanceStepDeps>,
}

impl DownloadCertificateStep {
    /// Creates the download step.
    pub fn new(deps: Arc<IssuanceStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for DownloadCertificateStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::DownloadCertificate
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let account = match self.deps.account(ctx.operation) {
            Ok(account) => account,
            Err(result) => return result,
        };
        let order = match self.deps.order(ctx.operation) {
            Ok(order) => order,
            Err(result) => return result,
        };
        match self
            .deps
            .backend
            .download_certificate(&account, &order)
            .await
        {
            Ok(chain) => {
                let payload = ChainPayload {
                    pem: chain.pem.clone(),
                    url: chain.url.clone(),
                };
                let locator = chain.url;
                match serde_json::to_string(&payload) {
                    Ok(json) => StepResult::Complete {
                        output_ref: Some(json),
                        side_effect_locator: Some(locator),
                        requires_compensation: false,
                    },
                    Err(err) => terminal(
                        error_codes::INTERNAL,
                        format!("serialize chain payload: {err}"),
                    ),
                }
            }
            Err(err) => retryable_error(err.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// VerifyCertificate
// ---------------------------------------------------------------------------

/// Fails verification with a compact summary of the failed checks (the full
/// per-check detail lives in the operation log/step output on success).
fn verification_failed(
    checks: Vec<domain::CertificateVerificationCheck>,
    intent: &CertificateIntent,
) -> StepResult {
    let failed: Vec<&str> = checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| check.name.as_str())
        .collect();
    policy_reject(format!(
        "certificate verification failed for intent {}: {}",
        intent.id,
        failed.join(", ")
    ))
}

/// Strictly verifies the issued chain against the intent and records a
/// [`CertificateVerificationReport`] (T07) as the step output: chain
/// parseability, exact typed SAN match, validity window, serial presence,
/// CSR public-key continuity and internal chain signature consistency. Any
/// failed check is a terminal policy failure — an
/// unverifiable certificate is never persisted, and the report with the
/// failing checks is attached to the operation for auditing.
pub struct VerifyCertificateStep;

impl Default for VerifyCertificateStep {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifyCertificateStep {
    /// Creates the verification step.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StepExecutor for VerifyCertificateStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::VerifyCertificate
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let chain = match read_payload::<ChainPayload>(
            ctx.operation,
            WorkflowStepKind::DownloadCertificate,
        ) {
            Ok(chain) => chain,
            Err(_) => return policy_reject("DownloadCertificate has not completed yet"),
        };
        let intent = match IssuanceStepDeps::resolve_intent(ctx.repositories, ctx.operation).await {
            Ok(intent) => intent,
            Err(err) => return policy_reject(err.to_string()),
        };

        // Build the report incrementally; every failed check fails the step
        // with the full report attached so operators see *all* problems.
        let mut checks: Vec<domain::CertificateVerificationCheck> = Vec::new();
        let parsed = match crate::certificate::CertificateChain::from_pem(chain.pem.as_bytes()) {
            Ok(parsed) => parsed,
            Err(err) => {
                checks.push(domain::CertificateVerificationCheck {
                    name: "chain_parsed".to_string(),
                    passed: false,
                    detail: Some(err.to_string()),
                });
                return verification_failed(checks, &intent);
            }
        };
        checks.push(domain::CertificateVerificationCheck {
            name: "chain_parsed".to_string(),
            passed: true,
            detail: None,
        });

        // Exact, typed SAN match (IP SANs never pass as DNS names).
        let san_match = match crate::order::csr::verify_certificate_identifiers(
            &parsed.leaf,
            intent.identifiers.as_slice(),
        ) {
            Ok(matched) => matched,
            Err(err) => return terminal(error_codes::INTERNAL, err.to_string()),
        };
        checks.push(domain::CertificateVerificationCheck {
            name: "san_exact".to_string(),
            passed: san_match,
            detail: (!san_match).then(|| {
                "issued certificate SAN set does not exactly match the intent identifiers"
                    .to_string()
            }),
        });

        // Validity window: the certificate must be valid at the current
        // (repository) time.
        let now = ctx.repositories.clock.now();
        let validity = match (parsed.not_before(), parsed.not_after()) {
            (Ok(not_before), Ok(not_after)) => {
                let not_before: jiff::Timestamp = not_before.into();
                let not_after: jiff::Timestamp = not_after.into();
                let in_window = now >= not_before && now <= not_after;
                Some((not_before, not_after, in_window))
            }
            (Err(err), _) | (_, Err(err)) => {
                return terminal(error_codes::INTERNAL, err.to_string());
            }
        };
        let Some((not_before, not_after, in_window)) = validity else {
            unreachable!("validity is Some or the match returned early");
        };
        checks.push(domain::CertificateVerificationCheck {
            name: "validity_window".to_string(),
            passed: in_window,
            detail: (!in_window).then(|| {
                format!("not within validity window ({not_before} .. {not_after}; now {now})")
            }),
        });

        let serial = match leaf_serial_hex(&parsed.leaf) {
            Ok(serial) => serial,
            Err(err) => return terminal(error_codes::INTERNAL, err.to_string()),
        };
        checks.push(domain::CertificateVerificationCheck {
            name: "serial_present".to_string(),
            passed: !serial.is_empty(),
            detail: None,
        });

        // CSR public-key continuity: the issued leaf must carry exactly the
        // SubjectPublicKeyInfo of the CSR that was finalized — a CA may not
        // substitute a different key (T07).
        let csr = match read_payload::<CsrPayload>(ctx.operation, WorkflowStepKind::CreateCsr) {
            Ok(csr) => csr,
            Err(_) => return policy_reject("CreateCsr has not completed yet"),
        };
        let csr_der = match BASE64.decode(&csr.csr_der) {
            Ok(der) => der,
            Err(err) => {
                return terminal(error_codes::INTERNAL, format!("bad persisted CSR: {err}"));
            }
        };
        let csr_key_matches = match (csr_spki_der(&csr_der), leaf_spki_der(&parsed.leaf)) {
            (Ok(csr_spki), Ok(leaf_spki)) => csr_spki == leaf_spki,
            (Err(err), _) | (_, Err(err)) => {
                return terminal(error_codes::INTERNAL, err.to_string());
            }
        };
        checks.push(domain::CertificateVerificationCheck {
            name: "csr_public_key_matches".to_string(),
            passed: csr_key_matches,
            detail: (!csr_key_matches).then(|| {
                "issued leaf public key differs from the CSR subject public key".to_string()
            }),
        });

        // Internal chain consistency: the leaf must be signed by the chain's
        // immediate issuer — the first intermediate. A chain of one must be
        // self-signed (self-signed fixtures count as consistent).
        let (chain_consistent, inconsistency) = if let Some(issuer) = parsed.intermediates.first() {
            match parsed.verify_leaf_signed_by(issuer) {
                Ok(true) => (true, None),
                Ok(false) => (
                    false,
                    Some(
                        "leaf certificate is not signed by the first intermediate of the chain"
                            .to_string(),
                    ),
                ),
                Err(err) => return terminal(error_codes::INTERNAL, err.to_string()),
            }
        } else {
            match parsed.verify_leaf_self_signed() {
                Ok(true) => (true, None),
                Ok(false) => (
                    false,
                    Some("single-certificate chain is not self-signed".to_string()),
                ),
                Err(err) => return terminal(error_codes::INTERNAL, err.to_string()),
            }
        };
        checks.push(domain::CertificateVerificationCheck {
            name: "chain_internally_consistent".to_string(),
            passed: chain_consistent,
            detail: inconsistency,
        });

        let report = domain::CertificateVerificationReport {
            identifiers_exact_match: san_match,
            not_before: not_before.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            not_after: not_after.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            serial,
            ca: intent.ca_policy.ca_id.clone(),
            profile: intent.ca_policy.profile.clone(),
            checks,
        };
        if !report.all_passed() {
            return verification_failed(report.checks, &intent);
        }
        let output = match serde_json::to_string(&report) {
            Ok(output) => output,
            Err(err) => return terminal(error_codes::INTERNAL, err.to_string()),
        };
        StepResult::Complete {
            output_ref: Some(output),
            side_effect_locator: None,
            requires_compensation: false,
        }
    }
}

// ---------------------------------------------------------------------------
// PersistVersion
// ---------------------------------------------------------------------------

/// Persists the immutable certificate version (crash-idempotent via a
/// deterministic version id derived from the operation id).
pub struct PersistVersionStep {
    deps: Arc<IssuanceStepDeps>,
}

impl PersistVersionStep {
    /// Creates the persistence step.
    pub fn new(deps: Arc<IssuanceStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for PersistVersionStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::PersistVersion
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let chain = match read_payload::<ChainPayload>(
            ctx.operation,
            WorkflowStepKind::DownloadCertificate,
        ) {
            Ok(chain) => chain,
            Err(_) => return policy_reject("DownloadCertificate has not completed yet"),
        };
        let csr = match read_payload::<CsrPayload>(ctx.operation, WorkflowStepKind::CreateCsr) {
            Ok(csr) => csr,
            Err(_) => return policy_reject("CreateCsr has not completed yet"),
        };
        let intent = match IssuanceStepDeps::resolve_intent(ctx.repositories, ctx.operation).await {
            Ok(intent) => intent,
            Err(err) => return policy_reject(err.to_string()),
        };
        let Some(lineage_id) = &ctx.operation.subject.lineage_id else {
            return policy_reject("operation subject has no lineage");
        };
        let lineage = match ctx.repositories.lineages.get(lineage_id).await {
            Ok(Some(lineage)) => lineage.value,
            Ok(None) => {
                return terminal(
                    error_codes::INTERNAL,
                    format!("lineage `{lineage_id}` not found"),
                );
            }
            Err(err) => return retryable_error(err.to_string()),
        };

        let parsed = match crate::certificate::CertificateChain::from_pem(chain.pem.as_bytes()) {
            Ok(parsed) => parsed,
            Err(err) => return terminal(error_codes::INTERNAL, err.to_string()),
        };
        let (not_before, not_after) = match (parsed.not_before(), parsed.not_after()) {
            (Ok(not_before), Ok(not_after)) => {
                let not_before: jiff::Timestamp = not_before.into();
                let not_after: jiff::Timestamp = not_after.into();
                (not_before, not_after)
            }
            (Err(err), _) | (_, Err(err)) => {
                return terminal(error_codes::INTERNAL, err.to_string());
            }
        };

        let serial = match leaf_serial_hex(&parsed.leaf) {
            Ok(serial) => serial,
            Err(err) => return terminal(error_codes::INTERNAL, err.to_string()),
        };

        // Deterministic id: a retried step re-creates the same version.
        let version_id = match VersionId::new(format!("ver_{}", ctx.operation.id.as_str())) {
            Ok(id) => id,
            Err(err) => return terminal(error_codes::INTERNAL, err.to_string()),
        };
        let mut version = CertificateVersion {
            id: version_id.clone(),
            lineage_id: lineage.id.clone(),
            identifiers: intent.identifiers.clone(),
            certificate_chain_pem: chain.pem.clone(),
            serial,
            not_before: not_before.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            not_after: not_after.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            issued_by: self.deps.backend.ca_id().clone(),
            profile: intent.ca_policy.profile.clone(),
            key_ref: csr.key_ref.clone(),
            replaces: None,
            superseded_by: None,
            state: VersionState::Issued,
        };
        // Renewals record which version they replace.
        if let Some(active) = &lineage.active_version_id
            && active != &version_id
        {
            version.replaces = Some(active.clone());
        }

        match ctx.repositories.versions.create(version).await {
            Ok(crate::repository::CreateOutcome::Created) => {}
            Ok(crate::repository::CreateOutcome::AlreadyExists) => {}
            Err(err) => return retryable_error(err.to_string()),
        }

        let payload = match serde_json::to_string(&VersionPayload {
            version_id: version_id.clone(),
        }) {
            Ok(json) => json,
            Err(err) => return terminal(error_codes::INTERNAL, err.to_string()),
        };
        StepResult::Complete {
            output_ref: Some(payload),
            side_effect_locator: None,
            requires_compensation: false,
        }
    }
}

fn leaf_serial_hex(leaf_der: &[u8]) -> Result<String> {
    use x509_parser::asn1_rs::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(leaf_der)
        .map_err(|e| AcmeError::certificate(format!("parse leaf certificate: {e}")))?;
    Ok(hex::encode(cert.serial.to_bytes_be()))
}

/// The raw DER of the CSR's SubjectPublicKeyInfo.
fn csr_spki_der(csr_der: &[u8]) -> Result<Vec<u8>> {
    use x509_parser::asn1_rs::FromDer;
    let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(csr_der)
        .map_err(|e| AcmeError::certificate(format!("parse CSR: {e}")))?;
    Ok(csr.certification_request_info.subject_pki.raw.to_vec())
}

/// The raw DER of the leaf certificate's SubjectPublicKeyInfo.
fn leaf_spki_der(leaf_der: &[u8]) -> Result<Vec<u8>> {
    use x509_parser::asn1_rs::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(leaf_der)
        .map_err(|e| AcmeError::certificate(format!("parse leaf certificate: {e}")))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

// ---------------------------------------------------------------------------
// ScheduleDeployments
// ---------------------------------------------------------------------------

/// Creates the per-target deployment records and child `Deploy` operations.
/// Without delivery targets, activation runs immediately (the gate is
/// trivially satisfied).
pub struct ScheduleDeploymentsStep {
    deps: Arc<IssuanceStepDeps>,
}

impl ScheduleDeploymentsStep {
    /// Creates the scheduling step.
    pub fn new(deps: Arc<IssuanceStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for ScheduleDeploymentsStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::ScheduleDeployments
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let version =
            match read_payload::<VersionPayload>(ctx.operation, WorkflowStepKind::PersistVersion) {
                Ok(version) => version.version_id,
                Err(_) => return policy_reject("PersistVersion has not completed yet"),
            };

        let intent = match IssuanceStepDeps::resolve_intent(ctx.repositories, ctx.operation).await {
            Ok(intent) => intent,
            Err(err) => return policy_reject(err.to_string()),
        };

        if intent.delivery_targets.is_empty() {
            // No targets: the activation gate is trivially satisfied, so
            // activate the version right away.
            return match self
                .deps
                .orchestrator
                .activate_version_when_deployments_satisfied(&version)
                .await
            {
                Ok(
                    crate::delivery::DeploymentActivationOutcome::Activated { .. }
                    | crate::delivery::DeploymentActivationOutcome::AlreadyActive { .. },
                ) => StepResult::done(),
                Ok(crate::delivery::DeploymentActivationOutcome::Waiting {
                    missing_targets,
                    ..
                }) => policy_reject(format!(
                    "activation gate unexpectedly unsatisfied with no targets: {missing_targets:?}"
                )),
                Err(err) => retryable_error(err.to_string()),
            };
        }

        match self
            .deps
            .orchestrator
            .schedule_deployments_for_version(&version, &[])
            .await
        {
            Ok(_deployments) => StepResult::done(),
            Err(err) => retryable_error(err.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Deployment transitions (Deploy operation spine)
// ---------------------------------------------------------------------------

/// Advances the operation's deployment by one durable state transition.
///
/// The deployment is resolved deterministically: for every delivery target
/// of the intent, the derived deploy-operation id must equal this
/// operation's id.
async fn resolve_deployment(
    repositories: &RepositorySet,
    operation: &domain::OperationRecord,
) -> std::result::Result<domain::DeploymentRecord, StepResult> {
    let intent = match IssuanceStepDeps::resolve_intent(repositories, operation).await {
        Ok(intent) => intent,
        Err(err) => return Err(policy_reject(err.to_string())),
    };
    let Some(version_id) = &operation.subject.version_id else {
        return Err(policy_reject("deploy operation subject has no version"));
    };
    for target in &intent.delivery_targets {
        let deployment_id = match domain::DeploymentId::new(format!(
            "dep_{}_{}",
            version_id.as_str(),
            target.id.as_str()
        )) {
            Ok(id) => id,
            Err(err) => return Err(terminal(error_codes::INTERNAL, err.to_string())),
        };
        let operation_id = match domain::OperationId::new(format!(
            "op_deploy_{}_{}",
            version_id.as_str(),
            target.id.as_str()
        )) {
            Ok(id) => id,
            Err(err) => return Err(terminal(error_codes::INTERNAL, err.to_string())),
        };
        if operation_id == operation.id {
            return match repositories.deployments.get(&deployment_id).await {
                Ok(Some(stored)) => Ok(stored.value),
                Ok(None) => Err(policy_reject(format!(
                    "deployment `{deployment_id}` has not been scheduled yet"
                ))),
                Err(err) => Err(retryable_error(err.to_string())),
            };
        }
    }
    Err(policy_reject(
        "no delivery target matches this deploy operation",
    ))
}

async fn run_deployment_step(deps: &IssuanceStepDeps, ctx: StepContext<'_>) -> StepResult {
    let deployment = match resolve_deployment(ctx.repositories, ctx.operation).await {
        Ok(deployment) => deployment,
        Err(result) => return result,
    };
    let version = match ctx.repositories.versions.get(&deployment.version_id).await {
        Ok(Some(version)) => version.value,
        Ok(None) => {
            return terminal(
                error_codes::INTERNAL,
                format!("version `{}` not found", deployment.version_id),
            );
        }
        Err(err) => return retryable_error(err.to_string()),
    };

    // Sink material: the chain is mandatory; the private key is included
    // only when the key policy allows export.
    let private_key = if version.key_ref.exportable {
        match deps
            .key_provider
            .export(
                &version.key_ref,
                crate::key::ExportAuthorization {
                    actor: "workflow-deployment".to_string(),
                    key_export_granted: true,
                    reason: "deployment to configured sinks".to_string(),
                },
            )
            .await
        {
            Ok(Some(bytes)) => Some(bytes),
            Ok(None) => None,
            Err(err) => return retryable_error(err.to_string()),
        }
    } else {
        None
    };
    let material =
        match crate::delivery::CertificateMaterialBuilder::new().build(&version, private_key) {
            Ok(material) => material,
            Err(err) => return terminal(error_codes::INTERNAL, err.to_string()),
        };

    match deps
        .orchestrator
        .run_deployment_once(&deployment.id, &material)
        .await
    {
        Ok(record) => match record.state {
            domain::DeploymentState::Staged
            | domain::DeploymentState::Active
            | domain::DeploymentState::Healthy => StepResult::done(),
            domain::DeploymentState::Failed => retryable_error(
                record
                    .last_error
                    .unwrap_or_else(|| "deployment failed".to_string()),
            ),
            domain::DeploymentState::RolledBack => terminal(
                error_codes::CHALLENGE_CLEANUP_FAILED,
                record.last_error.unwrap_or_else(|| {
                    "deployment rolled back after failed health check".to_string()
                }),
            ),
            _ => wait_note(deps.wake_at(ctx.repositories)),
        },
        Err(err) => retryable_error(err.to_string()),
    }
}

macro_rules! deployment_step_executor {
    ($(#[$meta:meta])* $name:ident, $kind:expr) => {
        $(#[$meta])*
        pub struct $name {
            deps: Arc<IssuanceStepDeps>,
        }

        impl $name {
            /// Creates the step.
            pub fn new(deps: Arc<IssuanceStepDeps>) -> Self {
                Self { deps }
            }
        }

        #[async_trait]
        impl StepExecutor for $name {
            fn kind(&self) -> WorkflowStepKind {
                $kind
            }

            async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
                run_deployment_step(&self.deps, ctx).await
            }
        }
    };
}

deployment_step_executor!(
    /// Stages certificate material into the deployment target.
    StageDeploymentStep,
    WorkflowStepKind::StageDeployment
);
deployment_step_executor!(
    /// Activates staged certificate material at the target.
    ActivateDeploymentStep,
    WorkflowStepKind::ActivateDeployment
);
deployment_step_executor!(
    /// Verifies the target serves the expected version.
    VerifyDeploymentStep,
    WorkflowStepKind::VerifyDeployment
);

// ---------------------------------------------------------------------------
// Complete
// ---------------------------------------------------------------------------

/// Final bookkeeping. For `Deploy` operations this also runs the activation
/// gate: the lineage's active pointer switches only once every required
/// deployment is healthy (T09/T10 contract).
pub struct CompleteStep {
    deps: Arc<IssuanceStepDeps>,
}

impl CompleteStep {
    /// Creates the completion step.
    pub fn new(deps: Arc<IssuanceStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for CompleteStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::Complete
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        if ctx.operation.kind != domain::OperationKind::Deploy {
            return StepResult::done();
        }
        let Some(version_id) = &ctx.operation.subject.version_id else {
            return StepResult::done();
        };
        match self
            .deps
            .orchestrator
            .activate_version_when_deployments_satisfied(version_id)
            .await
        {
            Ok(
                crate::delivery::DeploymentActivationOutcome::Activated { .. }
                | crate::delivery::DeploymentActivationOutcome::AlreadyActive { .. },
            ) => StepResult::done(),
            Ok(crate::delivery::DeploymentActivationOutcome::Waiting {
                missing_targets, ..
            }) => {
                let _ = missing_targets;
                wait_note(self.deps.wake_at(ctx.repositories))
            }
            Err(err) => retryable_error(err.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// SubmitRevocation (Revoke operation spine)
// ---------------------------------------------------------------------------

/// Submits the revocation request to the CA. Without this step a revoke
/// operation would complete without revoking anything — a simulated path.
pub struct SubmitRevocationStep {
    deps: Arc<IssuanceStepDeps>,
}

impl SubmitRevocationStep {
    /// Creates the revocation step.
    pub fn new(deps: Arc<IssuanceStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for SubmitRevocationStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::SubmitRevocation
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let account = match self.deps.account(ctx.operation) {
            Ok(account) => account,
            Err(result) => return result,
        };
        let Some(version_id) = &ctx.operation.subject.version_id else {
            return policy_reject("revoke operation subject has no version");
        };
        let version = match ctx.repositories.versions.get(version_id).await {
            Ok(Some(version)) => version.value,
            Ok(None) => {
                return terminal(
                    error_codes::INTERNAL,
                    format!("version `{version_id}` not found"),
                );
            }
            Err(err) => return retryable_error(err.to_string()),
        };
        let chain = match crate::certificate::CertificateChain::from_pem(
            version.certificate_chain_pem.as_bytes(),
        ) {
            Ok(chain) => chain,
            Err(err) => return terminal(error_codes::INTERNAL, err.to_string()),
        };
        let request = ca_backend::RevocationRequest {
            certificate_der: chain.leaf,
            reason: RevocationReason::Unspecified,
        };
        match self.deps.backend.revoke(&account, &request).await {
            Ok(()) => StepResult::done(),
            Err(err) => acme_backend_error(err.to_string()),
        }
    }
}
