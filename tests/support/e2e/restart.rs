use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use acmex::domain::{OperationId, WorkflowStepKind};
use acmex::workflow::{StepContext, StepExecutor, StepResult};

#[derive(Debug, Default)]
pub struct ExternalEffectLedger {
    calls: Mutex<BTreeMap<String, usize>>,
    creations: Mutex<BTreeMap<String, usize>>,
}

impl ExternalEffectLedger {
    pub fn ensure_once(&self, operation: &OperationId, step: WorkflowStepKind) -> String {
        let key = format!("{}:{}", operation.as_str(), step.as_str());
        *self
            .calls
            .lock()
            .expect("ledger calls lock poisoned")
            .entry(key.clone())
            .or_default() += 1;

        let mut creations = self
            .creations
            .lock()
            .expect("ledger creations lock poisoned");
        creations.entry(key.clone()).or_insert(1);
        format!("fake://{key}")
    }

    pub fn calls_for(&self, operation: &OperationId, step: WorkflowStepKind) -> usize {
        self.calls
            .lock()
            .expect("ledger calls lock poisoned")
            .get(&format!("{}:{}", operation.as_str(), step.as_str()))
            .copied()
            .unwrap_or_default()
    }

    pub fn creations_for(&self, operation: &OperationId, step: WorkflowStepKind) -> usize {
        self.creations
            .lock()
            .expect("ledger creations lock poisoned")
            .get(&format!("{}:{}", operation.as_str(), step.as_str()))
            .copied()
            .unwrap_or_default()
    }
}

pub struct IdempotentEffectExecutor {
    kind: WorkflowStepKind,
    ledger: Arc<ExternalEffectLedger>,
}

impl IdempotentEffectExecutor {
    pub fn new(kind: WorkflowStepKind, ledger: Arc<ExternalEffectLedger>) -> Self {
        Self { kind, ledger }
    }
}

#[async_trait]
impl StepExecutor for IdempotentEffectExecutor {
    fn kind(&self) -> WorkflowStepKind {
        self.kind
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        let locator = self.ledger.ensure_once(&ctx.operation.id, self.kind);
        StepResult::Complete {
            output_ref: None,
            side_effect_locator: Some(locator),
            requires_compensation: false,
        }
    }
}

pub struct PanicAfterEffectExecutor {
    kind: WorkflowStepKind,
    ledger: Arc<ExternalEffectLedger>,
}

impl PanicAfterEffectExecutor {
    pub fn new(kind: WorkflowStepKind, ledger: Arc<ExternalEffectLedger>) -> Self {
        Self { kind, ledger }
    }
}

#[async_trait]
impl StepExecutor for PanicAfterEffectExecutor {
    fn kind(&self) -> WorkflowStepKind {
        self.kind
    }

    async fn execute(&self, ctx: StepContext<'_>) -> StepResult {
        self.ledger.ensure_once(&ctx.operation.id, self.kind);
        panic!(
            "simulated crash after {} external effect and before repository save",
            self.kind.as_str()
        );
    }
}
