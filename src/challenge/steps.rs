//! Real workflow step executors for the validation pipeline (T05).
//!
//! These executors wire the [`WorkflowEngine`](crate::workflow) to the
//! [`CaBackend`](crate::ca_backend) and the [`PresenterRegistry`]. Steps
//! exchange data through persisted step outputs (JSON in the operation
//! record's `output_ref`), so the whole pipeline survives crashes:
//!
//! * `EnsureAccount` → `AccountHandle`
//! * `CreateOrResumeOrder` → `OrderHandle` (persisted before any external
//!   resource exists, so restarts resume instead of re-ordering)
//! * `LoadAuthorizations` → authorization resources (with challenge tokens)
//! * `PrepareChallenges` → challenge sessions + leases (compensated on
//!   cancel/failure)
//! * `WaitPropagation` / `AcknowledgeChallenges` / `WaitAuthorizations` →
//!   drive sessions to `Valid`
//! * `CleanupChallenges` → idempotent lease cleanup, always attempted
//!   regardless of the operation's outcome

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use jiff::Timestamp;

use crate::ca_backend::CaBackend;
use crate::ca_backend::{AccountHandle, AuthorizationRef, ChallengeRef, OrderHandle, OrderRequest};
use crate::domain::challenge::ChallengeLeaseState;
use crate::domain::{
    ClassifiedError, ErrorClass, OperationRecord, WorkflowStepKind, error_codes,
    validate_order_policy,
};
use crate::error::{AcmeError, Result};
use crate::protocol::Jwk;
use crate::repository::RepositorySet;
use crate::types::ChallengeType;
use crate::workflow::{CompensationResult, StepContext, StepExecutor, StepResult};

use super::presenter::{PrepareChallenge, PresenterRegistry};
use super::session::{ChallengeSession, ChallengeSessionState};

/// Shared dependencies of the validation pipeline steps.
pub struct ChallengeStepDeps {
    /// The CA to talk to.
    pub backend: Arc<dyn CaBackend>,
    /// Presenters by challenge type.
    pub presenters: PresenterRegistry,
    /// The account key's JWK (for key authorizations).
    pub account_jwk: Jwk,
    /// Identifier policy (allowed challenges; empty = any compatible).
    pub allowed_challenges: crate::domain::ChallengeSet,
    /// Maximum time from prepare to propagation.
    pub propagation_timeout: Duration,
    /// Re-observation interval while waiting for propagation.
    pub poll_interval: Duration,
}

impl ChallengeStepDeps {
    /// Computes the ACME key authorization `token.thumbprint`.
    fn key_authorization(&self, token: &str) -> Result<String> {
        Ok(format!(
            "{}.{}",
            token,
            self.account_jwk.thumbprint_sha256()?
        ))
    }
}

// ---------------------------------------------------------------------------
// persisted step payloads
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct AccountPayload {
    account: AccountHandle,
}

#[derive(Serialize, Deserialize)]
struct OrderPayload {
    order: OrderHandle,
}

#[derive(Serialize, Deserialize)]
struct AuthorizationsPayload {
    authorizations: Vec<AuthzSnapshot>,
}

/// Snapshot of one authorization, persisted between steps.
#[derive(Serialize, Deserialize)]
struct AuthzSnapshot {
    url: String,
    status: String,
    identifier: crate::domain::Identifier,
    challenges: Vec<ChallengeSnapshot>,
}

#[derive(Serialize, Deserialize)]
struct ChallengeSnapshot {
    #[serde(rename = "type")]
    challenge_type: String,
    url: String,
    token: String,
    status: String,
}

fn read_payload<T: serde::de::DeserializeOwned>(
    record: &OperationRecord,
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

fn policy_error(detail: impl Into<String>) -> StepResult {
    StepResult::Fail(ClassifiedError {
        code: error_codes::VALIDATION_CHALLENGE_INCOMPATIBLE,
        class: ErrorClass::PolicyViolation,
        detail: Some(detail.into()),
    })
}

fn retryable(detail: impl Into<String>) -> StepResult {
    StepResult::RetryAt {
        after: Duration::from_secs(1),
        error: ClassifiedError {
            code: error_codes::ACME_SERVER_ERROR,
            class: ErrorClass::Retryable,
            detail: Some(detail.into()),
        },
    }
}

// ---------------------------------------------------------------------------
// EnsureAccount
// ---------------------------------------------------------------------------

/// Ensures a reusable CA account exists.
pub struct EnsureAccountStep {
    deps: Arc<ChallengeStepDeps>,
    contacts: Vec<String>,
    terms_agreed: bool,
}

impl EnsureAccountStep {
    /// Creates the step with the account contacts.
    pub fn new(deps: Arc<ChallengeStepDeps>, contacts: Vec<String>, terms_agreed: bool) -> Self {
        Self {
            deps,
            contacts,
            terms_agreed,
        }
    }
}

#[async_trait]
impl StepExecutor for EnsureAccountStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::EnsureAccount
    }

    async fn execute(&self, _ctx: StepContext<'_>) -> StepResult {
        let account_ref = crate::ca_backend::AccountRef {
            tenant_id: "ten_default".to_string(),
            contacts: self.contacts.clone(),
            terms_of_service_agreed: self.terms_agreed,
            external_account_binding: None,
        };
        match self.deps.backend.ensure_account(&account_ref).await {
            Ok(handle) => {
                let payload =
                    serde_json::to_string(&AccountPayload { account: handle }).unwrap_or_default();
                StepResult::Complete {
                    output_ref: Some(payload),
                    side_effect_locator: None,
                    requires_compensation: false,
                }
            }
            Err(err) => retryable(err.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// CreateOrResumeOrder
// ---------------------------------------------------------------------------

/// Creates the ACME order (the workflow resumes a persisted order after a
/// crash instead of creating a new one — the handle lives in the step
/// output, which is written before later steps run).
pub struct CreateOrderStep {
    deps: Arc<ChallengeStepDeps>,
    identifiers: Vec<crate::domain::Identifier>,
}

impl CreateOrderStep {
    /// Creates the step for the given identifiers.
    pub fn new(deps: Arc<ChallengeStepDeps>, identifiers: Vec<crate::domain::Identifier>) -> Self {
        Self { deps, identifiers }
    }
}

#[async_trait]
impl StepExecutor for CreateOrderStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::CreateOrResumeOrder
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        // Idempotency: a persisted handle from a previous attempt wins.
        if let Ok(payload) =
            read_payload::<OrderPayload>(ctx.operation, WorkflowStepKind::CreateOrResumeOrder)
            && ctx
                .operation
                .steps
                .iter()
                .any(|s| s.kind == WorkflowStepKind::CreateOrResumeOrder && s.output_ref.is_some())
        {
            return StepResult::Complete {
                output_ref: None,
                side_effect_locator: Some(payload.order.url),
                requires_compensation: false,
            };
        }

        let account =
            match read_payload::<AccountPayload>(ctx.operation, WorkflowStepKind::EnsureAccount) {
                Ok(payload) => payload.account,
                Err(_) => return policy_error("EnsureAccount has not completed yet"),
            };

        let request = OrderRequest::for_identifiers(self.identifiers.clone());
        match self.deps.backend.create_order(&account, &request).await {
            Ok(handle) => {
                let payload = serde_json::to_string(&OrderPayload {
                    order: handle.clone(),
                })
                .unwrap_or_default();
                StepResult::Complete {
                    output_ref: Some(payload),
                    side_effect_locator: Some(handle.url),
                    requires_compensation: false,
                }
            }
            Err(err) => retryable(err.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// LoadAuthorizations
// ---------------------------------------------------------------------------

/// Loads all authorizations of the order (with challenge tokens).
pub struct LoadAuthorizationsStep {
    deps: Arc<ChallengeStepDeps>,
}

impl LoadAuthorizationsStep {
    /// Creates the step.
    pub fn new(deps: Arc<ChallengeStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for LoadAuthorizationsStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::LoadAuthorizations
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let account =
            match read_payload::<AccountPayload>(ctx.operation, WorkflowStepKind::EnsureAccount) {
                Ok(payload) => payload.account,
                Err(_) => return policy_error("EnsureAccount has not completed yet"),
            };
        let order = match read_payload::<OrderPayload>(
            ctx.operation,
            WorkflowStepKind::CreateOrResumeOrder,
        ) {
            Ok(payload) => payload.order,
            Err(_) => return policy_error("CreateOrResumeOrder has not completed yet"),
        };

        match self.deps.backend.get_authorizations(&account, &order).await {
            Ok(resources) => {
                let authorizations = resources
                    .iter()
                    .map(|resource| AuthzSnapshot {
                        url: resource.url.clone(),
                        status: resource.authorization.status.clone(),
                        identifier: resource.authorization.identifier.clone(),
                        challenges: resource
                            .authorization
                            .challenges
                            .iter()
                            .map(|c| ChallengeSnapshot {
                                challenge_type: c.challenge_type.clone(),
                                url: c.url.clone(),
                                token: c.token.clone(),
                                status: c.status.clone(),
                            })
                            .collect(),
                    })
                    .collect();
                let payload = serde_json::to_string(&AuthorizationsPayload { authorizations })
                    .unwrap_or_default();
                StepResult::Complete {
                    output_ref: Some(payload),
                    side_effect_locator: None,
                    requires_compensation: false,
                }
            }
            Err(err) => retryable(err.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// PrepareChallenges
// ---------------------------------------------------------------------------

/// Creates external resources for every authorization; each session is
/// independent and persisted, with crash-idempotent session ids.
pub struct PrepareChallengesStep {
    deps: Arc<ChallengeStepDeps>,
}

impl PrepareChallengesStep {
    /// Creates the step.
    pub fn new(deps: Arc<ChallengeStepDeps>) -> Self {
        Self { deps }
    }
}

/// Deterministic session id: stable across retries of the same operation.
fn session_id(operation: &OperationRecord, authorization_url: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(authorization_url.as_bytes());
    format!(
        "chs_{}_{}",
        operation.id.as_str(),
        &hex::encode(hasher.finalize())[..8]
    )
}

#[async_trait]
impl StepExecutor for PrepareChallengesStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::PrepareChallenges
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let payload = match read_payload::<AuthorizationsPayload>(
            ctx.operation,
            WorkflowStepKind::LoadAuthorizations,
        ) {
            Ok(payload) => payload,
            Err(_) => return policy_error("LoadAuthorizations has not completed yet"),
        };
        let repositories = ctx.repositories;

        // Per-identifier validation plan rejects impossible combinations
        // before creating any external resource.
        let identifiers: Vec<_> = payload
            .authorizations
            .iter()
            .map(|a| a.identifier.clone())
            .collect();
        let policy = crate::domain::ValidationPolicy {
            allowed_challenges: self.deps.allowed_challenges.clone(),
            ..Default::default()
        };
        // The CA offers the union of all authorizations' challenges.
        let mut offered = crate::domain::ChallengeSet::default();
        for authz in &payload.authorizations {
            for challenge in &authz.challenges {
                if let Ok(kind) = challenge.challenge_type.parse::<ChallengeType>() {
                    offered.insert(kind);
                }
            }
        }
        let plan = match validate_order_policy(&identifiers, &offered, &policy) {
            Ok(plan) => plan,
            Err(err) => return policy_error(err.to_string()),
        };

        for authz in &payload.authorizations {
            let id = session_id(ctx.operation, &authz.url);

            // Crash idempotency: sessions whose external resource already
            // exists are not re-prepared. A `Preparing` session (transient
            // failure or crash mid-prepare) IS re-attempted — prepare is
            // idempotent per session id and resource value.
            if let Ok(Some(stored)) = repositories.challenge_sessions.get(&id).await
                && matches!(
                    stored.value.state,
                    ChallengeSessionState::Prepared
                        | ChallengeSessionState::Observing
                        | ChallengeSessionState::Propagated
                        | ChallengeSessionState::Acknowledged
                        | ChallengeSessionState::Processing
                        | ChallengeSessionState::Valid
                )
            {
                continue;
            }

            // Choose the challenge for this identifier.
            let plan_item = plan
                .items
                .iter()
                .find(|item| item.identifier == authz.identifier)
                .cloned()
                .unwrap_or_else(|| {
                    // Wildcard authorizations come back for the base name.
                    plan.items
                        .iter()
                        .find(|item| {
                            item.identifier.as_dns().is_some()
                                && authz.identifier.as_dns().is_some()
                                && item.identifier.as_dns().unwrap().base_name()
                                    == authz.identifier.as_dns().unwrap().base_name()
                        })
                        .cloned()
                        .expect("plan covers every authorization identifier")
                });
            let chosen = authz.challenges.iter().find(|c| {
                plan_item
                    .allowed
                    .iter()
                    .any(|allowed| allowed.as_str() == c.challenge_type)
            });
            let Some(chosen) = chosen else {
                return policy_error(format!(
                    "CA offers no compatible challenge for `{}`",
                    authz.identifier
                ));
            };
            let challenge_type: ChallengeType = match chosen.challenge_type.parse() {
                Ok(kind) => kind,
                Err(_) => return policy_error("unknown challenge type"),
            };
            let Some(presenter) = self.deps.presenters.get(challenge_type) else {
                return policy_error(format!("no presenter registered for `{challenge_type}`"));
            };

            let mut session = ChallengeSession {
                id: id.clone(),
                operation_id: ctx.operation.id.clone(),
                authorization_url: authz.url.clone(),
                challenge_url: chosen.url.clone(),
                identifier: authz.identifier.clone(),
                challenge_type,
                token_hash: ChallengeSession::hash_token(&chosen.token),
                state: ChallengeSessionState::Selected,
                lease_id: None,
                deadline: repositories
                    .clock
                    .now()
                    .checked_add(
                        jiff::Span::new().seconds(self.deps.propagation_timeout.as_secs() as i64),
                    )
                    .expect("deadline overflow"),
                last_error: None,
            };

            // Persist the session before creating the external resource.
            let _ = repositories
                .challenge_sessions
                .create(session.clone())
                .await;
            session = session
                .transition(ChallengeSessionState::Preparing)
                .expect("selected -> preparing");
            if let Some(stored) = repositories.challenge_sessions.get(&id).await.unwrap() {
                let _ = repositories
                    .challenge_sessions
                    .update(stored.revision, session.clone())
                    .await;
            }

            let key_authorization = match self.deps.key_authorization(&chosen.token) {
                Ok(value) => value,
                Err(err) => return retryable(err.to_string()),
            };
            match presenter
                .prepare(PrepareChallenge {
                    session: session.clone(),
                    key_authorization,
                })
                .await
            {
                Ok(lease) => {
                    let _ = repositories.challenge_leases.create(lease.clone()).await;
                    let prepared = session
                        .transition(ChallengeSessionState::Prepared)
                        .expect("preparing -> prepared");
                    if let Some(stored) = repositories.challenge_sessions.get(&id).await.unwrap() {
                        let mut updated = prepared;
                        updated.lease_id = Some(lease.id);
                        let _ = repositories
                            .challenge_sessions
                            .update(stored.revision, updated)
                            .await;
                    }
                }
                Err(err) => {
                    // Transient provider failure: stay in Preparing so the
                    // retry re-attempts idempotently.
                    if let Some(stored) = repositories.challenge_sessions.get(&id).await.unwrap() {
                        let mut updated = session.clone();
                        updated.last_error = Some(err.to_string());
                        let _ = repositories
                            .challenge_sessions
                            .update(stored.revision, updated)
                            .await;
                    }
                    return retryable(format!("prepare failed for `{}`: {err}", authz.identifier));
                }
            }
        }

        StepResult::complete_with_locator(format!("challenges://{}", ctx.operation.id.as_str()))
    }

    async fn compensate(&self, ctx: StepContext<'_>) -> CompensationResult {
        match cleanup_operation_leases(&self.deps.presenters, ctx.repositories, ctx.operation).await
        {
            Ok(_) => CompensationResult::Done,
            Err(err) => CompensationResult::RetryLater {
                after: Duration::from_secs(5),
                error: err.to_string(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// WaitPropagation
// ---------------------------------------------------------------------------

/// Observes every session's external resource until quorum (here: the
/// presenter's observation) or deadline.
pub struct WaitPropagationStep {
    deps: Arc<ChallengeStepDeps>,
}

impl WaitPropagationStep {
    /// Creates the step.
    pub fn new(deps: Arc<ChallengeStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for WaitPropagationStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::WaitPropagation
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let repositories = ctx.repositories;
        let sessions = repositories
            .challenge_sessions
            .list_by_operation(&ctx.operation.id)
            .await
            .unwrap_or_default();
        if sessions.is_empty() {
            return policy_error("no challenge sessions to observe");
        }

        let now = repositories.clock.now();
        let mut next_check: Option<Timestamp> = None;
        for stored in &sessions {
            let session = &stored.value;
            if session.state == ChallengeSessionState::Propagated {
                continue;
            }
            if session.is_past_deadline(now) {
                let failed = session.transition(ChallengeSessionState::Failed).ok();
                if let Some(failed) = failed
                    && let Some(current) = repositories
                        .challenge_sessions
                        .get(&session.id)
                        .await
                        .unwrap()
                {
                    let mut updated = failed;
                    updated.last_error = Some("propagation deadline exceeded".to_string());
                    let _ = repositories
                        .challenge_sessions
                        .update(current.revision, updated)
                        .await;
                }
                return StepResult::Fail(ClassifiedError {
                    code: error_codes::CHALLENGE_PROPAGATION_TIMEOUT,
                    class: ErrorClass::Terminal,
                    detail: Some(format!(
                        "propagation timed out for `{}`",
                        session.identifier
                    )),
                });
            }

            let Some(lease_id) = session.lease_id.clone() else {
                return retryable("session lease missing");
            };
            let Some(lease) = repositories
                .challenge_leases
                .get(&lease_id)
                .await
                .ok()
                .flatten()
                .map(|l| l.value)
            else {
                return retryable("session lease missing");
            };
            let Some(presenter) = self.deps.presenters.get(session.challenge_type) else {
                return policy_error("no presenter for session");
            };

            // First observation moves Prepared -> Observing.
            let current = if session.state == ChallengeSessionState::Prepared {
                let observing = session
                    .transition(ChallengeSessionState::Observing)
                    .expect("prepared -> observing");
                if let Some(fresh) = repositories
                    .challenge_sessions
                    .get(&session.id)
                    .await
                    .unwrap()
                {
                    let _ = repositories
                        .challenge_sessions
                        .update(fresh.revision, observing.clone())
                        .await;
                }
                observing
            } else {
                session.clone()
            };

            match presenter.observe(&lease).await {
                Ok(crate::challenge::Observation::Propagated) => {
                    let propagated = current
                        .transition(ChallengeSessionState::Propagated)
                        .expect("observing -> propagated");
                    if let Some(fresh) = repositories
                        .challenge_sessions
                        .get(&session.id)
                        .await
                        .unwrap()
                    {
                        let _ = repositories
                            .challenge_sessions
                            .update(fresh.revision, propagated)
                            .await;
                    }
                }
                Ok(crate::challenge::Observation::NotYet { retry_after }) => {
                    let retry_at = now
                        .checked_add(jiff::Span::new().milliseconds(retry_after.as_millis() as i64))
                        .expect("retry overflow");
                    next_check = Some(
                        next_check.map_or(retry_at, |earliest: Timestamp| earliest.min(retry_at)),
                    );
                }
                Err(err) => return retryable(err.to_string()),
            }
        }

        match next_check {
            Some(until) => StepResult::WaitUntil {
                until,
                note: Some("propagation not yet visible".to_string()),
            },
            None => StepResult::done(),
        }
    }
}

// ---------------------------------------------------------------------------
// AcknowledgeChallenges
// ---------------------------------------------------------------------------

/// Tells the CA to start validating each session's challenge.
pub struct AcknowledgeChallengesStep {
    deps: Arc<ChallengeStepDeps>,
}

impl AcknowledgeChallengesStep {
    /// Creates the step.
    pub fn new(deps: Arc<ChallengeStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for AcknowledgeChallengesStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::AcknowledgeChallenges
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let account =
            match read_payload::<AccountPayload>(ctx.operation, WorkflowStepKind::EnsureAccount) {
                Ok(payload) => payload.account,
                Err(_) => return policy_error("EnsureAccount has not completed yet"),
            };
        let repositories = ctx.repositories;
        let sessions = repositories
            .challenge_sessions
            .list_by_operation(&ctx.operation.id)
            .await
            .unwrap_or_default();

        for stored in sessions {
            let session = stored.value;
            if session.state != ChallengeSessionState::Propagated {
                continue; // already acknowledged or not yet propagated
            }
            let result = self
                .deps
                .backend
                .acknowledge_challenge(
                    &account,
                    &ChallengeRef {
                        url: session.challenge_url.clone(),
                        challenge_type: session.challenge_type.as_str().to_string(),
                    },
                )
                .await;
            match result {
                Ok(()) => {
                    let acknowledged = session
                        .transition(ChallengeSessionState::Acknowledged)
                        .expect("propagated -> acknowledged");
                    if let Some(fresh) = repositories
                        .challenge_sessions
                        .get(&session.id)
                        .await
                        .unwrap()
                    {
                        let _ = repositories
                            .challenge_sessions
                            .update(fresh.revision, acknowledged)
                            .await;
                    }
                }
                Err(err) => return retryable(err.to_string()),
            }
        }
        StepResult::done()
    }
}

// ---------------------------------------------------------------------------
// WaitAuthorizations
// ---------------------------------------------------------------------------

/// Polls each authorization until valid/invalid. Invalid authorizations
/// fail the operation — cleanup still runs via the final step and the
/// prepare-step compensation.
pub struct WaitAuthorizationsStep {
    deps: Arc<ChallengeStepDeps>,
}

impl WaitAuthorizationsStep {
    /// Creates the step.
    pub fn new(deps: Arc<ChallengeStepDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl StepExecutor for WaitAuthorizationsStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::WaitAuthorizations
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let account =
            match read_payload::<AccountPayload>(ctx.operation, WorkflowStepKind::EnsureAccount) {
                Ok(payload) => payload.account,
                Err(_) => return policy_error("EnsureAccount has not completed yet"),
            };
        let repositories = ctx.repositories;
        let sessions = repositories
            .challenge_sessions
            .list_by_operation(&ctx.operation.id)
            .await
            .unwrap_or_default();

        let now = repositories.clock.now();
        let mut pending = false;
        for stored in sessions {
            let session = stored.value;
            if session.state == ChallengeSessionState::Valid {
                continue;
            }
            let result = self
                .deps
                .backend
                .get_authorization(
                    &account,
                    &AuthorizationRef {
                        url: session.authorization_url.clone(),
                    },
                )
                .await;
            match result {
                Ok(resource) => match resource.authorization.status.as_str() {
                    "valid" => {
                        // Processing -> Valid.
                        let processing = if session.state == ChallengeSessionState::Acknowledged {
                            let processing = session
                                .transition(ChallengeSessionState::Processing)
                                .expect("acknowledged -> processing");
                            if let Some(fresh) = repositories
                                .challenge_sessions
                                .get(&session.id)
                                .await
                                .unwrap()
                            {
                                let _ = repositories
                                    .challenge_sessions
                                    .update(fresh.revision, processing.clone())
                                    .await;
                            }
                            processing
                        } else {
                            session.clone()
                        };
                        let valid = processing
                            .transition(ChallengeSessionState::Valid)
                            .expect("processing -> valid");
                        if let Some(fresh) = repositories
                            .challenge_sessions
                            .get(&session.id)
                            .await
                            .unwrap()
                        {
                            let _ = repositories
                                .challenge_sessions
                                .update(fresh.revision, valid)
                                .await;
                        }
                    }
                    "invalid" => {
                        let failed = session.transition(ChallengeSessionState::Failed).ok();
                        if let Some(failed) = failed
                            && let Some(fresh) = repositories
                                .challenge_sessions
                                .get(&session.id)
                                .await
                                .unwrap()
                        {
                            let mut updated = failed;
                            updated.last_error = Some("authorization invalid".to_string());
                            let _ = repositories
                                .challenge_sessions
                                .update(fresh.revision, updated)
                                .await;
                        }
                        return StepResult::Fail(ClassifiedError {
                            code: error_codes::VALIDATION_CHALLENGE_INCOMPATIBLE,
                            class: ErrorClass::Terminal,
                            detail: Some(format!(
                                "CA marked authorization invalid for `{}`",
                                session.identifier
                            )),
                        });
                    }
                    _ => pending = true,
                },
                Err(err) => return retryable(err.to_string()),
            }
        }

        if pending {
            StepResult::WaitUntil {
                until: now
                    .checked_add(
                        jiff::Span::new().milliseconds(self.deps.poll_interval.as_millis() as i64),
                    )
                    .expect("poll overflow"),
                note: Some("authorization still pending".to_string()),
            }
        } else {
            StepResult::done()
        }
    }
}

// ---------------------------------------------------------------------------
// CleanupChallenges
// ---------------------------------------------------------------------------

/// Final-step cleanup of every lease; idempotent, retryable and always
/// attempted regardless of the operation's earlier outcome.
pub struct CleanupChallengesStep {
    deps: Arc<ChallengeStepDeps>,
}

impl CleanupChallengesStep {
    /// Creates the step.
    pub fn new(deps: Arc<ChallengeStepDeps>) -> Self {
        Self { deps }
    }
}

/// Cleans all leases of one operation (shared by the step and the prepare
/// compensation).
pub async fn cleanup_operation_leases(
    presenters: &PresenterRegistry,
    repositories: &RepositorySet,
    operation: &OperationRecord,
) -> Result<usize> {
    let sessions = repositories
        .challenge_sessions
        .list_by_operation(&operation.id)
        .await?;
    let mut cleaned = 0;
    for stored in sessions {
        let session = stored.value;
        let Some(lease_id) = session.lease_id.clone() else {
            continue;
        };
        let Some(lease_stored) = repositories.challenge_leases.get(&lease_id).await? else {
            continue;
        };
        let lease = lease_stored.value;
        if lease.state == ChallengeLeaseState::Cleaned {
            continue;
        }
        let Some(presenter) = presenters.get(lease.challenge_type) else {
            continue;
        };
        match presenter.cleanup(&lease).await {
            Ok(_) => {
                let now = repositories.clock.now();
                let mut updated = lease.clone();
                updated.state = ChallengeLeaseState::Cleaned;
                updated.cleaned_at = Some(now);
                let _ = repositories
                    .challenge_leases
                    .update(lease_stored.revision, updated)
                    .await;
                // Sessions record the cleanup dimension too.
                let mut session_updated = session.clone();
                session_updated.state = ChallengeSessionState::Cleaned;
                let _ = repositories
                    .challenge_sessions
                    .update(stored.revision, session_updated)
                    .await;
                cleaned += 1;
            }
            Err(err) => {
                let mut updated = lease.clone();
                updated.cleanup_attempts += 1;
                updated.last_cleanup_error = Some(err.to_string());
                updated.state = ChallengeLeaseState::CleanupPending;
                let _ = repositories
                    .challenge_leases
                    .update(lease_stored.revision, updated)
                    .await;
                return Err(AcmeError::challenge(
                    lease.challenge_type.as_str().to_string(),
                    err.to_string(),
                ));
            }
        }
    }
    Ok(cleaned)
}

#[async_trait]
impl StepExecutor for CleanupChallengesStep {
    fn kind(&self) -> WorkflowStepKind {
        WorkflowStepKind::CleanupChallenges
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        match cleanup_operation_leases(&self.deps.presenters, ctx.repositories, ctx.operation).await
        {
            Ok(_) => StepResult::done(),
            Err(err) => StepResult::RetryAt {
                after: Duration::from_secs(5),
                error: ClassifiedError {
                    code: error_codes::CHALLENGE_CLEANUP_FAILED,
                    class: ErrorClass::Retryable,
                    detail: Some(err.to_string()),
                },
            },
        }
    }
}
