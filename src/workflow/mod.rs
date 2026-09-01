//! Durable workflow engine: step-wise, persisted, resumable operations.
//!
//! The engine advances [`OperationRecord`]s **one step at a time**, with
//! every step start and completion persisted through the repository
//! (T02). A process can crash between any two writes; on restart the same
//! operation resumes from its persisted state without re-executing
//! completed steps and without blindly retrying whole flows.
//!
//! Key invariants:
//!
//! * A worker only advances an operation while holding its lease
//!   (`op:<id>`), and re-reads the latest revision after acquiring it —
//!   stale writers lose the CAS and their result is dropped.
//! * Waiting (CA polling, DNS propagation) is expressed as `wake_at`, not
//!   as a sleeping task.
//! * Failures carry a stable [`ClassifiedError`]; retryable classes use
//!   exponential backoff with jitter, `RateLimited` honors `Retry-After`.
//! * Cancellation is a *request*: the worker acknowledges it at the next
//!   step boundary, then runs compensations for steps that created
//!   external resources.
//!
//! Roadmap T04–T07 plug real executors (CA backend, challenge presenters)
//! into this engine; `issue.rs` provides the skeleton with no-op executors.

pub mod engine;
pub mod issue;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use jiff::Timestamp;

use crate::domain::{ClassifiedError, OperationRecord, WorkflowStepKind};
use crate::repository::RepositorySet;

pub use engine::{EngineConfig, WorkflowEngine};
pub use issue::IssueWorkflow;

type ExecuteFn = dyn for<'ctx> Fn(StepContext<'ctx>) -> StepResult + Send + Sync;
type CompensateFn = dyn for<'ctx> Fn(StepContext<'ctx>) -> CompensationResult + Send + Sync;

/// Input to a step executor.
pub struct StepContext<'a> {
    /// The operation being advanced (latest persisted state).
    pub operation: &'a OperationRecord,
    /// Repository access for steps that need to read/write entities.
    pub repositories: &'a RepositorySet,
}

impl<'a> StepContext<'a> {
    /// The current step kind.
    pub fn step_kind(&self) -> WorkflowStepKind {
        self.operation
            .current_step()
            .map(|step| step.kind)
            .expect("operation always has a current step")
    }
}

/// Outcome of one step execution.
#[derive(Debug, Clone)]
pub enum StepResult {
    /// The step finished; the workflow advances to the next step.
    Complete {
        /// Reference to the step's persisted output, if any.
        output_ref: Option<String>,
        /// Locator of an external side effect created by this step
        /// (persisted immediately for crash recovery).
        side_effect_locator: Option<String>,
        /// The step created an external resource that must be compensated
        /// on failure/cancel.
        requires_compensation: bool,
    },
    /// The step is waiting on an external event until `until`.
    WaitUntil {
        /// When the operation should become ready again.
        until: Timestamp,
        /// Why it waits (diagnostics only).
        note: Option<String>,
    },
    /// The step failed retryably; retry after a delay.
    RetryAt {
        /// How long to wait before the next attempt.
        after: Duration,
        /// The classified error.
        error: ClassifiedError,
    },
    /// The step failed terminally; the operation fails.
    Fail(ClassifiedError),
}

impl StepResult {
    /// Convenience: a completing step with no output or side effects.
    pub fn done() -> Self {
        Self::Complete {
            output_ref: None,
            side_effect_locator: None,
            requires_compensation: false,
        }
    }

    /// A completing step that created a compensatable external resource.
    pub fn complete_with_locator(locator: impl Into<String>) -> Self {
        Self::Complete {
            output_ref: None,
            side_effect_locator: Some(locator.into()),
            requires_compensation: true,
        }
    }
}

/// Outcome of a compensation run.
#[derive(Debug, Clone)]
pub enum CompensationResult {
    /// The external resource is gone (or was never created).
    Done,
    /// Cleanup failed retryably.
    RetryLater {
        /// How long to wait before the next cleanup attempt.
        after: Duration,
        /// What went wrong (no secrets).
        error: String,
    },
    /// Cleanup is impossible; requires operator action.
    Fail(String),
}

/// One step of a workflow, executed by the engine.
#[async_trait]
pub trait StepExecutor: Send + Sync {
    /// Which step this executor handles.
    fn kind(&self) -> WorkflowStepKind;

    /// Executes the step for the given operation.
    async fn execute(&self, ctx: StepContext<'_>) -> StepResult;

    /// Compensates (cleans up) the step's external side effect. Must be
    /// idempotent: an already-absent resource is `Done`.
    async fn compensate(&self, _ctx: StepContext<'_>) -> CompensationResult {
        CompensationResult::Done
    }
}

/// A closure-backed executor, handy for tests and simple steps.
pub struct FnStepExecutor {
    step_kind: WorkflowStepKind,
    execute_fn: Arc<ExecuteFn>,
    compensate_fn: Option<Arc<CompensateFn>>,
}

impl FnStepExecutor {
    /// Creates an executor from an execution closure.
    pub fn new<F>(step_kind: WorkflowStepKind, execute_fn: F) -> Self
    where
        F: for<'ctx> Fn(StepContext<'ctx>) -> StepResult + Send + Sync + 'static,
    {
        Self {
            step_kind,
            execute_fn: Arc::new(execute_fn),
            compensate_fn: None,
        }
    }

    /// Attaches a compensation closure.
    pub fn with_compensate<F>(mut self, compensate_fn: F) -> Self
    where
        F: for<'ctx> Fn(StepContext<'ctx>) -> CompensationResult + Send + Sync + 'static,
    {
        self.compensate_fn = Some(Arc::new(compensate_fn));
        self
    }
}

#[async_trait]
impl StepExecutor for FnStepExecutor {
    fn kind(&self) -> WorkflowStepKind {
        self.step_kind
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        (self.execute_fn)(ctx)
    }

    async fn compensate(&self, ctx: StepContext<'_>) -> CompensationResult {
        match &self.compensate_fn {
            Some(f) => f(ctx),
            None => CompensationResult::Done,
        }
    }
}

/// Exponential backoff with jitter for retryable failures.
///
/// `attempt` is 1-based: the first retry waits ~`base`, doubling each time,
/// capped at `max`. Jitter is deterministic per (attempt, seed) so tests
/// stay reproducible.
pub fn compute_backoff(attempt: u32, base: Duration, max: Duration, seed: u64) -> Duration {
    let exp = attempt.saturating_sub(1).min(16);
    let factor = 2u64.saturating_pow(exp);
    let raw = base
        .as_millis()
        .saturating_mul(factor as u128)
        .max(1)
        .min(max.as_millis().max(1));
    // Deterministic jitter in [0.75, 1.25) of the raw delay.
    let jitter_unit = raw / 8;
    let jitter = if jitter_unit == 0 {
        0u128
    } else {
        ((seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(attempt as u64)
            % 2) as u128)
            * jitter_unit
    };
    Duration::from_millis((raw + jitter) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded_and_grows() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        for attempt in 1..=10 {
            let delay = compute_backoff(attempt, base, max, 42);
            let expected =
                (base.as_millis() * 2u128.pow((attempt - 1).min(16))).min(max.as_millis());
            // Jitter stays within [0.75, 1.25) of the exponential value.
            assert!(
                delay.as_millis() >= expected * 3 / 4,
                "attempt {attempt}: {delay:?} below lower bound"
            );
            assert!(
                delay.as_millis() <= expected * 5 / 4,
                "attempt {attempt}: {delay:?} above upper bound"
            );
            assert!(delay <= max * 2, "delay is capped near max");
        }
        // Capped eventually, regardless of attempt count.
        assert!(compute_backoff(40, base, max, 1) <= max * 2);
    }
}
