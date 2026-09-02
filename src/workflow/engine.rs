//! The worker engine: picks ready operations, executes one step, persists.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::domain::{
    ClassifiedError, CompensationState, ErrorClass, OperationId, OperationRecord, OperationStatus,
    StepRecord, StepStatus, WorkflowStepKind, error_codes,
};
use crate::error::{AcmeError, Result};
use crate::repository::{
    CasOutcome, CreateOutcome, LeaseOutcome, RepositorySet, Revision, repository_error_class,
};
use tracing::Instrument;

use super::{CompensationResult, StepContext, StepExecutor, StepResult, compute_backoff};

/// Tuning knobs for the engine.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Lease TTL for operation processing.
    pub lease_ttl: Duration,
    /// Maximum attempts per step before terminal failure.
    pub max_step_attempts: u32,
    /// Base backoff for retryable step failures.
    pub retry_backoff_base: Duration,
    /// Maximum backoff for retryable step failures.
    pub retry_backoff_max: Duration,
    /// Maximum compensation attempts before `CompensationFailed`.
    pub max_compensation_attempts: u32,
    /// How many ready operations one polling cycle may process.
    pub batch_size: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            lease_ttl: Duration::from_secs(60),
            max_step_attempts: 3,
            retry_backoff_base: Duration::from_secs(2),
            retry_backoff_max: Duration::from_secs(300),
            max_compensation_attempts: 3,
            batch_size: 16,
        }
    }
}

/// The durable workflow engine.
pub struct WorkflowEngine {
    worker_id: String,
    repositories: RepositorySet,
    executors: HashMap<WorkflowStepKind, Arc<dyn StepExecutor>>,
    config: EngineConfig,
    metrics: Option<crate::metrics::SharedMetrics>,
}

impl WorkflowEngine {
    /// Creates an engine over a repository set.
    pub fn new(worker_id: impl Into<String>, repositories: RepositorySet) -> Self {
        Self {
            worker_id: worker_id.into(),
            repositories,
            executors: HashMap::new(),
            config: EngineConfig::default(),
            metrics: None,
        }
    }

    /// Overrides tuning.
    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    /// Attaches the shared metrics registry (T11): operation terminal
    /// outcomes and per-step durations are recorded with low-cardinality
    /// labels.
    pub fn with_metrics(mut self, metrics: crate::metrics::SharedMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Registers a step executor.
    pub fn register(&mut self, executor: Arc<dyn StepExecutor>) {
        self.executors.insert(executor.kind(), executor);
    }

    /// The engine configuration.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// The engine's worker identity.
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// Submits a new operation (idempotent per operation id).
    ///
    /// Emits an `operation.created` outbox event on first submission.
    pub async fn submit(&self, record: OperationRecord) -> Result<OperationId> {
        match self.repositories.operations.create(record.clone()).await? {
            CreateOutcome::Created => {
                self.repositories
                    .outbox
                    .append(
                        "operation.created",
                        serde_json::json!({
                            "operation_id": record.id.as_str(),
                            "kind": record.kind.as_str(),
                        }),
                        None,
                    )
                    .await?;
                Ok(record.id)
            }
            CreateOutcome::AlreadyExists => Ok(record.id),
        }
    }

    /// Requests cancellation. Returns whether the request was applied.
    ///
    /// Cancellation is asynchronous: the worker observes the request at the
    /// next step boundary, then compensates steps with external resources.
    pub async fn request_cancel(&self, id: &OperationId) -> Result<bool> {
        loop {
            let Some(stored) = self.repositories.operations.get(id).await? else {
                return Ok(false);
            };
            if stored.value.status.is_terminal() {
                return Ok(false);
            }
            if stored.value.status == OperationStatus::CancelRequested {
                return Ok(true);
            }
            let next = stored
                .value
                .transition(OperationStatus::CancelRequested)
                .map_err(AcmeError::Storage)?;
            match self
                .repositories
                .operations
                .update(stored.revision, next)
                .await?
            {
                CasOutcome::Updated(_) => return Ok(true),
                CasOutcome::Conflict { .. } => continue, // re-read and retry
            }
        }
    }

    /// Processes up to `batch_size` ready operations, one step each.
    ///
    /// Returns the number of operations advanced.
    pub async fn run_once(&self) -> Result<usize> {
        let now = self.repositories.clock.now();
        let ready = match self
            .repositories
            .operations
            .list_ready(now, self.config.batch_size)
            .await
        {
            Ok(ready) => ready,
            Err(err) => {
                self.record_repository_error(&err);
                return Err(err);
            }
        };
        let mut advanced = 0;
        for stored in ready {
            match self.process_one(&stored.value, stored.revision).await {
                Ok(true) => advanced += 1,
                Ok(false) => {}
                Err(err) => {
                    // Repository failure (step failures arrive as
                    // classified `StepResult`s, never as `Err`).
                    self.record_repository_error(&err);
                    tracing::warn!(
                        operation = stored.value.id.as_str(),
                        error = %err,
                        "failed to advance operation"
                    );
                }
            }
        }
        Ok(advanced)
    }

    /// Advances exactly one operation by one step (or one compensation
    /// pass). Returns `false` when nothing was done (not ready / lease
    /// held). This is also the crash-recovery test entry point.
    pub async fn run_step(&self, id: &OperationId) -> Result<bool> {
        let Some(stored) = (match self.repositories.operations.get(id).await {
            Ok(stored) => stored,
            Err(err) => {
                self.record_repository_error(&err);
                return Err(err);
            }
        }) else {
            return Ok(false);
        };
        match self.process_one(&stored.value, stored.revision).await {
            Ok(advanced) => Ok(advanced),
            Err(err) => {
                self.record_repository_error(&err);
                Err(err)
            }
        }
    }

    /// Runs the operation to a terminal state, polling `run_step` until
    /// `timeout`. Compatibility facade for the legacy synchronous
    /// orchestrator API; new code should submit + poll asynchronously.
    pub async fn run_until_terminal(
        &self,
        id: &OperationId,
        timeout: Duration,
    ) -> Result<OperationRecord> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            self.run_step(id).await?;
            if let Some(stored) = self.repositories.operations.get(id).await?
                && stored.value.status.is_terminal()
            {
                return Ok(stored.value);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(AcmeError::Timeout(format!(
                    "operation {id} did not reach a terminal state in {:?}",
                    timeout
                )));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Spawns the background worker loop. Stops when `shutdown` resolves.
    pub fn spawn(
        self: &Arc<Self>,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
        poll_interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut shutdown = std::pin::pin!(shutdown);
            loop {
                tokio::select! {
                    _ = shutdown.as_mut() => break,
                    _ = tokio::time::sleep(poll_interval) => {
                        if let Err(err) = engine.run_once().await {
                            tracing::warn!(error = %err, "workflow poll cycle failed");
                        }
                    }
                }
            }
            tracing::info!(worker = engine.worker_id(), "workflow worker stopped");
        })
    }

    // -----------------------------------------------------------------
    // internals
    // -----------------------------------------------------------------

    fn lease_key(id: &OperationId) -> String {
        format!("op/{}", id.as_str())
    }

    async fn process_one(&self, operation: &OperationRecord, revision: Revision) -> Result<bool> {
        // Wrap the whole advancement (lease, re-read, step execution, persist)
        // in the convention span. Entering a span guard across `.await` is
        // unsound in async code, so the work runs as an instrumented future:
        // `Instrument` re-enters the span on every poll, keeping the fields
        // attached across all awaits below.
        self.process_one_inner(operation, revision)
            .instrument(operation_span(operation))
            .await
    }

    async fn process_one_inner(
        &self,
        operation: &OperationRecord,
        revision: Revision,
    ) -> Result<bool> {
        if operation.status.is_terminal() {
            return Ok(false);
        }

        // Acquire the processing lease; single-host workers still go through
        // the lease interface so multi-instance setups need no restructuring.
        let lease_key = Self::lease_key(&operation.id);
        let grant = match self
            .repositories
            .leases
            .acquire(&lease_key, &self.worker_id, self.config.lease_ttl)
            .await?
        {
            LeaseOutcome::Granted(grant) => grant,
            LeaseOutcome::HeldByOther { owner, .. } => {
                tracing::debug!(
                    operation = operation.id.as_str(),
                    owner,
                    "operation leased elsewhere"
                );
                return Ok(false);
            }
        };

        // Re-read the latest state after acquiring the lease; our revision
        // may already be stale.
        let Some(stored) = self.repositories.operations.get(&operation.id).await? else {
            self.release(&lease_key, &grant).await;
            return Ok(false);
        };
        let mut record = stored.value;
        let mut record_revision = stored.revision;
        if record.status.is_terminal() || !record.is_ready_at(self.repositories.clock.now()) {
            self.release(&lease_key, &grant).await;
            return Ok(false);
        }

        // Compensating operations re-enter the cancellation handler when
        // their cleanup retry wake_at passes.
        let advanced = if record.status == OperationStatus::CancelRequested
            || record.status == OperationStatus::Compensating
        {
            self.handle_cancellation(&mut record, &mut record_revision)
                .await?
        } else {
            self.execute_current_step(&mut record, &mut record_revision)
                .await?
        };

        self.release(&lease_key, &grant).await;
        let _ = revision; // initial revision intentionally unused after re-read
        Ok(advanced)
    }

    async fn release(&self, key: &str, grant: &crate::repository::LeaseGrant) {
        let token = grant.fencing_token;
        if let Err(err) = self
            .repositories
            .leases
            .release(key, &self.worker_id, token)
            .await
        {
            tracing::warn!(key, error = %err, "failed to release operation lease");
        }
    }

    async fn save(&self, record: &OperationRecord, expected: &mut Revision) -> Result<bool> {
        match self
            .repositories
            .operations
            .update(*expected, record.clone())
            .await?
        {
            CasOutcome::Updated(rev) => {
                *expected = rev;
                Ok(true)
            }
            CasOutcome::Conflict { .. } => {
                tracing::warn!(
                    operation = record.id.as_str(),
                    "lost race while advancing operation; dropping this worker's result"
                );
                Ok(false)
            }
        }
    }

    async fn execute_current_step(
        &self,
        record: &mut OperationRecord,
        revision: &mut Revision,
    ) -> Result<bool> {
        let Some(step) = record.steps.get(record.current_step_index).cloned() else {
            // No current step: treat as success.
            return self
                .finish(record, revision, OperationStatus::Succeeded, None)
                .await;
        };
        // Step-level span, instrumented over the async body for the same
        // soundness reasons as `process_one`.
        let span = step_span(record, step.kind);
        self.execute_step(record, revision, step)
            .instrument(span)
            .await
    }

    async fn execute_step(
        &self,
        record: &mut OperationRecord,
        revision: &mut Revision,
        step: StepRecord,
    ) -> Result<bool> {
        // Queued -> Running on first activity; Waiting -> Running on wake.
        if record.status != OperationStatus::Running {
            *record = record
                .transition(OperationStatus::Running)
                .map_err(AcmeError::Storage)?;
        }

        let Some(executor) = self.executors.get(&step.kind).cloned() else {
            let error = ClassifiedError {
                code: error_codes::INTERNAL,
                class: ErrorClass::Terminal,
                detail: Some(format!(
                    "no executor registered for step `{}`",
                    step.kind.as_str()
                )),
            };
            return self
                .finish(record, revision, OperationStatus::Failed, Some(error))
                .await;
        };

        // Persist step start (crash marker: attempt in flight).
        let mut started = record.clone();
        let step_index = record.current_step_index;
        {
            let step_mut = &mut started.steps[step_index];
            step_mut.attempt += 1;
            step_mut.status = StepStatus::Running;
            step_mut.started_at = Some(self.repositories.clock.now());
            step_mut.finished_at = None;
        }
        if !self.save(&started, revision).await? {
            return Ok(false); // lost race
        }
        *record = started;

        // Execute.
        let ctx = StepContext {
            operation: record,
            repositories: &self.repositories,
        };
        let step_started = std::time::Instant::now();
        let result = executor.execute(ctx).await;
        self.record_step_duration(step.kind, &result, step_started.elapsed());
        let now = self.repositories.clock.now();

        match result {
            StepResult::Complete {
                output_ref,
                side_effect_locator,
                requires_compensation,
            } => {
                let mut updated = record.clone();
                {
                    let step_mut = &mut updated.steps[step_index];
                    step_mut.status = StepStatus::Completed;
                    step_mut.finished_at = Some(now);
                    step_mut.error = None;
                    step_mut.output_ref = output_ref;
                    step_mut.side_effect_locator = side_effect_locator;
                    step_mut.compensation = if requires_compensation {
                        CompensationState::Pending
                    } else {
                        CompensationState::NotRequired
                    };
                }
                let last_step = step_index + 1 >= updated.steps.len();
                if last_step {
                    updated.wake_at = None;
                    *record = updated;
                    return self
                        .finish(record, revision, OperationStatus::Succeeded, None)
                        .await;
                }
                updated.current_step_index += 1;
                updated.wake_at = None;
                updated.updated_at = now;
                if !self.save(&updated, revision).await? {
                    return Ok(false);
                }
                *record = updated;
                self.emit_step_event(record, step.kind, "completed").await;
                Ok(true)
            }
            StepResult::WaitUntil { until, note } => {
                let mut updated = record.clone();
                {
                    let step_mut = &mut updated.steps[step_index];
                    step_mut.status = StepStatus::Pending; // waiting, not failed
                    if let Some(note) = note {
                        step_mut.output_ref = Some(format!("waiting: {note}"));
                    }
                }
                updated.status = OperationStatus::Waiting;
                updated.wake_at = Some(until);
                updated.updated_at = now;
                if !self.save(&updated, revision).await? {
                    return Ok(false);
                }
                *record = updated;
                self.emit_step_event(record, step.kind, "waiting").await;
                Ok(true)
            }
            StepResult::RetryAt { after, error } => {
                let attempt = record.steps[step_index].attempt;
                if attempt >= self.config.max_step_attempts {
                    return self
                        .finish(record, revision, OperationStatus::Failed, Some(error))
                        .await;
                }
                let local_wake = now
                    .checked_add(
                        jiff::Span::new()
                            .milliseconds(after.as_millis().min(i64::MAX as u128) as i64),
                    )
                    .expect("retry backoff overflow");
                let wake = match &error.class {
                    // Server-provided Retry-After wins over local backoff.
                    ErrorClass::RateLimited {
                        retry_after: Some(at),
                    } if *at > now => *at,
                    _ => {
                        let backoff_wake = now
                            .checked_add(
                                jiff::Span::new().milliseconds(
                                    compute_backoff(
                                        attempt,
                                        self.config.retry_backoff_base,
                                        self.config.retry_backoff_max,
                                        record.id.as_str().len() as u64,
                                    )
                                    .as_millis()
                                    .min(i64::MAX as u128)
                                        as i64,
                                ),
                            )
                            .expect("retry backoff overflow");
                        local_wake.max(backoff_wake)
                    }
                };
                let mut updated = record.clone();
                {
                    let step_mut = &mut updated.steps[step_index];
                    step_mut.status = StepStatus::Failed;
                    step_mut.error = Some(error);
                }
                updated.status = OperationStatus::Waiting;
                updated.wake_at = Some(wake);
                updated.updated_at = now;
                if !self.save(&updated, revision).await? {
                    return Ok(false);
                }
                *record = updated;
                self.emit_step_event(record, step.kind, "retry_scheduled")
                    .await;
                Ok(true)
            }
            StepResult::Fail(error) => {
                // Failures still owe compensation for created resources
                // (prepare registered it); only after cleanup does the
                // operation reach its terminal state.
                self.finish_with_compensation(
                    record,
                    revision,
                    OperationStatus::Failed,
                    Some(error),
                )
                .await
            }
        }
    }

    async fn handle_cancellation(
        &self,
        record: &mut OperationRecord,
        revision: &mut Revision,
    ) -> Result<bool> {
        // Enter Compensating, clean up pending compensations, then cancel.
        *record = record
            .transition(OperationStatus::Compensating)
            .map_err(AcmeError::Storage)?;
        if !self.save(record, revision).await? {
            return Ok(false);
        }

        if !self.run_compensations(record, revision).await? {
            return Ok(true); // another cleanup pass is scheduled
        }
        let compensation_failed = record
            .steps
            .iter()
            .any(|s| s.compensation == CompensationState::Failed);
        let terminal = if compensation_failed {
            OperationStatus::CompensationFailed
        } else {
            OperationStatus::Cancelled
        };
        let error = if compensation_failed {
            Some(ClassifiedError {
                code: error_codes::CHALLENGE_CLEANUP_FAILED,
                class: ErrorClass::OperatorActionRequired,
                detail: Some("cleanup of external resources failed".to_string()),
            })
        } else {
            None
        };
        self.finish(record, revision, terminal, error).await
    }

    /// One compensation pass over pending steps (reverse order).
    /// Returns `false` when another pass was scheduled via `wake_at`.
    async fn run_compensations(
        &self,
        record: &mut OperationRecord,
        revision: &mut Revision,
    ) -> Result<bool> {
        let mut compensation_failed = false;
        for index in (0..record.steps.len()).rev() {
            if record.steps[index].compensation != CompensationState::Pending {
                continue;
            }
            let kind = record.steps[index].kind;
            let Some(executor) = self.executors.get(&kind).cloned() else {
                // Without the executor we cannot clean up: keep it pending.
                compensation_failed = true;
                continue;
            };
            record.steps[index].compensation_attempts += 1;
            let ctx = StepContext {
                operation: record,
                repositories: &self.repositories,
            };
            match executor.compensate(ctx).await {
                CompensationResult::Done => {
                    record.steps[index].compensation = CompensationState::Done;
                }
                CompensationResult::RetryLater { after, error } => {
                    if record.steps[index].compensation_attempts
                        >= self.config.max_compensation_attempts
                    {
                        record.steps[index].compensation = CompensationState::Failed;
                        tracing::error!(
                            operation = record.id.as_str(),
                            step = kind.as_str(),
                            error,
                            "compensation exhausted; operator action required"
                        );
                    } else {
                        record.steps[index].compensation = CompensationState::Pending;
                        // Reschedule another compensation pass.
                        record.wake_at = Some(
                            self.repositories
                                .clock
                                .now()
                                .checked_add(
                                    jiff::Span::new().milliseconds(after.as_millis() as i64),
                                )
                                .expect("compensation backoff overflow"),
                        );
                    }
                }
                CompensationResult::Fail(error) => {
                    record.steps[index].compensation = CompensationState::Failed;
                    tracing::error!(
                        operation = record.id.as_str(),
                        step = kind.as_str(),
                        error,
                        "compensation terminally failed"
                    );
                }
            }
        }
        if record
            .steps
            .iter()
            .any(|s| s.compensation == CompensationState::Pending)
        {
            // More compensation passes needed later.
            record.updated_at = self.repositories.clock.now();
            self.save(record, revision).await?;
            return Ok(false);
        }
        let _ = compensation_failed;
        Ok(true)
    }

    /// Runs pending compensations (if any) and then terminates the
    /// operation with `status`. Used for failures; cancellation goes through
    /// `handle_cancellation`.
    async fn finish_with_compensation(
        &self,
        record: &mut OperationRecord,
        revision: &mut Revision,
        status: OperationStatus,
        error: Option<ClassifiedError>,
    ) -> Result<bool> {
        let has_pending = record
            .steps
            .iter()
            .any(|s| s.compensation == CompensationState::Pending);
        if !has_pending {
            return self.finish(record, revision, status, error).await;
        }

        // Enter Compensating first (legal from any non-terminal state).
        if record.status != OperationStatus::Compensating {
            *record = record
                .transition(OperationStatus::Compensating)
                .map_err(AcmeError::Storage)?;
            if !self.save(record, revision).await? {
                return Ok(false);
            }
        }
        loop {
            if !self.run_compensations(record, revision).await? {
                return Ok(true); // cleanup pass rescheduled via wake_at
            }
            if record
                .steps
                .iter()
                .any(|s| s.compensation == CompensationState::Pending)
            {
                continue;
            }
            break;
        }
        if record
            .steps
            .iter()
            .any(|s| s.compensation == CompensationState::Failed)
        {
            record.error = Some(ClassifiedError {
                code: error_codes::CHALLENGE_CLEANUP_FAILED,
                class: ErrorClass::OperatorActionRequired,
                detail: Some("cleanup of external resources failed".to_string()),
            });
            return self
                .finish(record, revision, OperationStatus::CompensationFailed, None)
                .await;
        }
        // Compensating -> Failed/Cancelled is a legal terminal transition
        // once compensation has drained.
        self.finish(record, revision, status, error).await
    }

    /// Moves the operation to a terminal state, emitting an outbox event.
    async fn finish(
        &self,
        record: &mut OperationRecord,
        revision: &mut Revision,
        status: OperationStatus,
        error: Option<ClassifiedError>,
    ) -> Result<bool> {
        *record = record.transition(status).map_err(AcmeError::Storage)?;
        record.error = error;
        record.wake_at = None;
        record.updated_at = self.repositories.clock.now();
        if !self.save(record, revision).await? {
            return Ok(false);
        }
        self.record_operation_terminal(record);
        self.repositories
            .outbox
            .append(
                "operation.finished",
                serde_json::json!({
                    "operation_id": record.id.as_str(),
                    "status": record.status.as_str(),
                    "error_code": record.error.as_ref().map(|e| e.code.as_str()),
                }),
                None,
            )
            .await?;
        Ok(true)
    }

    /// Records `acmex_repository_errors_total` for a repository failure
    /// observed while listing, loading or advancing operations (T11).
    fn record_repository_error(&self, err: &AcmeError) {
        let Some(metrics) = &self.metrics else {
            return;
        };
        metrics
            .repository_errors_total
            .with_label_values(&[self.repositories.backend, repository_error_class(err)])
            .inc();
    }

    /// Records `acmex_operations_total` for terminal outcomes.
    fn record_operation_terminal(&self, record: &OperationRecord) {
        let Some(metrics) = &self.metrics else {
            return;
        };
        let (result, class) = match record.status {
            OperationStatus::Succeeded => ("succeeded", "none"),
            OperationStatus::Failed => ("failed", terminal_error_class(record)),
            OperationStatus::Cancelled => ("cancelled", "none"),
            OperationStatus::CompensationFailed => {
                ("compensation_failed", "operator_action_required")
            }
            _ => return,
        };
        metrics
            .operations_total
            .with_label_values(&[record.kind.as_str(), result, class])
            .inc();
    }

    /// Records `acmex_operation_step_duration_seconds` for one execution.
    fn record_step_duration(
        &self,
        step: WorkflowStepKind,
        result: &StepResult,
        elapsed: std::time::Duration,
    ) {
        let Some(metrics) = &self.metrics else {
            return;
        };
        let (outcome, class) = match result {
            StepResult::Complete { .. } => ("completed", "none"),
            StepResult::WaitUntil { .. } => ("waiting", "none"),
            StepResult::RetryAt { error, .. } => {
                ("retry_scheduled", error_class_label(&error.class))
            }
            StepResult::Fail(error) => ("failed", error_class_label(&error.class)),
        };
        metrics
            .operation_step_duration_seconds
            .with_label_values(&[step.as_str(), outcome, class])
            .observe(elapsed.as_secs_f64());
    }

    async fn emit_step_event(
        &self,
        record: &OperationRecord,
        step: WorkflowStepKind,
        outcome: &str,
    ) {
        let _ = self
            .repositories
            .outbox
            .append(
                "operation.step",
                serde_json::json!({
                    "operation_id": record.id.as_str(),
                    "step": step.as_str(),
                    "outcome": outcome,
                }),
                None,
            )
            .await;
    }
}

/// Low-cardinality label for an error class (metrics convention).
fn error_class_label(class: &ErrorClass) -> &'static str {
    match class {
        ErrorClass::Retryable => "retryable",
        ErrorClass::RateLimited { .. } => "rate_limited",
        ErrorClass::Terminal => "terminal",
        ErrorClass::PolicyViolation => "policy_violation",
        ErrorClass::OperatorActionRequired => "operator_action_required",
        ErrorClass::Cancelled => "cancelled",
    }
}

/// Error class label for a terminally finished operation.
fn terminal_error_class(record: &OperationRecord) -> &'static str {
    record
        .error
        .as_ref()
        .map(|e| error_class_label(&e.class))
        .unwrap_or("none")
}

// ---------------------------------------------------------------------
// trace spans (T11 convention, see docs/SECURITY_OBSERVABILITY_HA.md)
// ---------------------------------------------------------------------

/// Records the optional `OperationSubject` identifier fields onto a span
/// that declared them as `field::Empty`.
///
/// Only convention fields for values that actually exist are recorded.
/// `tenant_id` is intentionally omitted: it lives on the intent/lineage,
/// not on the operation record. Tokens, key material and caller-supplied
/// identifiers (`idempotency_key`, `request_hash`) are never recorded.
fn record_subject_fields(span: &tracing::Span, record: &OperationRecord) {
    if let Some(id) = &record.subject.intent_id {
        span.record("intent_id", tracing::field::display(id));
    }
    if let Some(id) = &record.subject.lineage_id {
        span.record("lineage_id", tracing::field::display(id));
    }
    if let Some(id) = &record.subject.version_id {
        span.record("version_id", tracing::field::display(id));
    }
}

/// Operation-level span for one worker advancement pass.
///
/// DEBUG level on purpose: a span is emitted for every step advancement
/// (17 per issuance), so INFO would dominate default deployments; lifecycle
/// signal already flows through outbox events and metrics. Fields snapshot
/// the record at pickup — identifiers are immutable once assigned.
fn operation_span(record: &OperationRecord) -> tracing::Span {
    let span = tracing::debug_span!(
        "workflow.operation",
        operation_id = %record.id,
        kind = %record.kind.as_str(),
        intent_id = tracing::field::Empty,
        lineage_id = tracing::field::Empty,
        version_id = tracing::field::Empty,
    );
    record_subject_fields(&span, record);
    span
}

/// Step-level span for the execution of the current workflow step.
///
/// DEBUG level, mirroring `workflow.operation` (per-step spans are even
/// more frequent than operation passes).
fn step_span(record: &OperationRecord, step: WorkflowStepKind) -> tracing::Span {
    let span = tracing::debug_span!(
        "workflow.step",
        operation_id = %record.id,
        kind = %record.kind.as_str(),
        workflow_step = %step.as_str(),
        intent_id = tracing::field::Empty,
        lineage_id = tracing::field::Empty,
        version_id = tracing::field::Empty,
    );
    record_subject_fields(&span, record);
    span
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_config_defaults() {
        let config = EngineConfig::default();
        assert_eq!(config.max_step_attempts, 3);
        assert_eq!(config.batch_size, 16);
        assert!(config.retry_backoff_base < config.retry_backoff_max);
    }
}
