//! Issuance workflow skeleton (T03).
//!
//! Registers an executor for every step of the issuance spine. Until the
//! real adapters land (T04 CA backend, T05 challenge lifecycle, T10
//! sinks), each executor is an explicit **no-op** that completes without
//! external side effects — the engine behavior (persistence, retry,
//! cancel, compensation, resume) is fully exercisable against them.
//!
//! `IssueWorkflow::skeleton()` is also the reference for how later tasks
//! replace individual steps: register a real `StepExecutor` for a kind and
//! the engine picks it up.

use std::sync::Arc;

use crate::domain::WorkflowStepKind;

use super::{FnStepExecutor, StepExecutor, StepResult};

/// Builder for the issuance workflow's executor set.
pub struct IssueWorkflow;

impl IssueWorkflow {
    /// The full skeleton: every spine step completes as a no-op.
    ///
    /// `PrepareChallenges` registers a compensation (also a no-op) so
    /// cancellation flows are observable in tests.
    pub fn skeleton() -> Vec<Arc<dyn StepExecutor>> {
        Self::skeleton_with_overrides(std::collections::HashMap::new())
    }

    /// The skeleton with per-kind overrides; useful when one or two steps
    /// need real behavior (e.g. a failing `FinalizeOrder` in tests).
    pub fn skeleton_with_overrides(
        overrides: std::collections::HashMap<WorkflowStepKind, Arc<dyn StepExecutor>>,
    ) -> Vec<Arc<dyn StepExecutor>> {
        WorkflowStepKind::issuance_spine()
            .iter()
            .filter_map(|kind| match overrides.get(kind) {
                Some(executor) => Some(Arc::clone(executor)),
                None => Some(Self::noop(*kind)),
            })
            .collect()
    }

    /// A single no-op executor.
    pub fn noop(kind: WorkflowStepKind) -> Arc<dyn StepExecutor> {
        match kind {
            WorkflowStepKind::PrepareChallenges => Arc::new(
                FnStepExecutor::new(kind, |_| {
                    // The skeleton's "external resource" is a stable fake
                    // locator so compensation wiring is visible in records.
                    StepResult::complete_with_locator("skeleton://challenge")
                })
                .with_compensate(|_| super::CompensationResult::Done),
            ),
            WorkflowStepKind::CreateOrResumeOrder => {
                Arc::new(FnStepExecutor::new(kind, |_| StepResult::Complete {
                    output_ref: None,
                    side_effect_locator: Some("skeleton://order/resumed".to_string()),
                    requires_compensation: false,
                }))
            }
            _ => Arc::new(FnStepExecutor::new(kind, |_| StepResult::done())),
        }
    }
}
