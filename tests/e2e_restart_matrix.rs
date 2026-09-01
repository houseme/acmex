mod support;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use acmex::domain::{
    OperationId, OperationKind, OperationRecord, OperationStatus, OperationSubject, StepStatus,
    WorkflowStepKind,
};
use acmex::repository::{CreateOutcome, FakeClock, MemoryRepository, RepositorySet};
use acmex::workflow::{IssueWorkflow, StepExecutor, WorkflowEngine};
use jiff::Timestamp;
use support::e2e::restart::{
    ExternalEffectLedger, IdempotentEffectExecutor, PanicAfterEffectExecutor,
};

fn clock() -> Arc<FakeClock> {
    Arc::new(FakeClock::at(
        Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
    ))
}

fn register_spine(
    worker: &str,
    set: RepositorySet,
    replacement: Option<Arc<dyn StepExecutor>>,
) -> WorkflowEngine {
    let mut engine = WorkflowEngine::new(worker, set);
    let replacement_kind = replacement.as_ref().map(|executor| executor.kind());
    for kind in WorkflowStepKind::issuance_spine() {
        if Some(*kind) == replacement_kind {
            engine.register(replacement.as_ref().unwrap().clone());
        } else {
            engine.register(IssueWorkflow::noop(*kind));
        }
    }
    engine
}

async fn submit(set: &RepositorySet) -> OperationId {
    let id = OperationId::generate();
    let record = OperationRecord::new(
        id.clone(),
        OperationKind::Issue,
        OperationSubject::empty(),
        Some(format!("restart-matrix-{}", id.as_str())),
        None,
        set.clock.now(),
    );
    assert_eq!(
        set.operations.create(record).await.unwrap(),
        CreateOutcome::Created
    );
    id
}

async fn operation(set: &RepositorySet, id: &OperationId) -> OperationRecord {
    set.operations.get(id).await.unwrap().unwrap().value
}

async fn drive_to_step(
    engine: &WorkflowEngine,
    set: &RepositorySet,
    id: &OperationId,
    index: usize,
) {
    let mut guard = 0;
    while operation(set, id).await.current_step_index < index {
        assert!(engine.run_step(id).await.unwrap());
        guard += 1;
        assert!(guard < 64, "operation did not reach target index {index}");
    }
}

async fn assert_terminal_success(engine: &WorkflowEngine, set: &RepositorySet, id: &OperationId) {
    let record = engine
        .run_until_terminal(id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(record.status, OperationStatus::Succeeded);
    assert!(
        record
            .steps
            .iter()
            .all(|step| step.status == StepStatus::Completed)
    );
    assert_eq!(operation(set, id).await.status, OperationStatus::Succeeded);
}

#[tokio::test]
async fn restart_matrix_covers_every_issuance_step_and_crash_window() {
    for (index, step) in WorkflowStepKind::issuance_spine()
        .iter()
        .copied()
        .enumerate()
    {
        crash_before_external_call_resumes(step, index).await;
        crash_after_external_call_before_repository_save_is_idempotent(step, index).await;
        crash_after_repository_save_does_not_reexecute_completed_step(step, index).await;
    }
}

async fn crash_before_external_call_resumes(step: WorkflowStepKind, index: usize) {
    let fake_clock = clock();
    let set = MemoryRepository::with_clock(fake_clock).into_set();
    let ledger = Arc::new(ExternalEffectLedger::default());
    let target: Arc<dyn StepExecutor> =
        Arc::new(IdempotentEffectExecutor::new(step, ledger.clone()));
    let engine = register_spine("before", set.clone(), Some(target));
    let id = submit(&set).await;

    drive_to_step(&engine, &set, &id, index).await;
    drop(engine);

    let restarted = register_spine(
        "before-restart",
        set.clone(),
        Some(Arc::new(IdempotentEffectExecutor::new(
            step,
            ledger.clone(),
        ))),
    );
    assert_terminal_success(&restarted, &set, &id).await;
    assert_eq!(ledger.creations_for(&id, step), 1);
    assert_eq!(ledger.calls_for(&id, step), 1);
}

async fn crash_after_external_call_before_repository_save_is_idempotent(
    step: WorkflowStepKind,
    index: usize,
) {
    let fake_clock = clock();
    let set = MemoryRepository::with_clock(fake_clock.clone()).into_set();
    let ledger = Arc::new(ExternalEffectLedger::default());
    let crashing: Arc<dyn StepExecutor> =
        Arc::new(PanicAfterEffectExecutor::new(step, ledger.clone()));
    let engine = register_spine("after-external", set.clone(), Some(crashing));
    let id = submit(&set).await;

    drive_to_step(&engine, &set, &id, index).await;
    let crash_id = id.clone();
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let handle = tokio::spawn(async move { engine.run_step(&crash_id).await });
    let join = handle.await;
    std::panic::set_hook(previous_hook);
    assert!(
        join.is_err(),
        "simulated crash must panic at {}",
        step.as_str()
    );
    assert_eq!(ledger.creations_for(&id, step), 1);

    fake_clock.advance_secs(120);
    let restarted = register_spine(
        "after-external-restart",
        set.clone(),
        Some(Arc::new(IdempotentEffectExecutor::new(
            step,
            ledger.clone(),
        ))),
    );
    assert_terminal_success(&restarted, &set, &id).await;
    assert_eq!(
        ledger.creations_for(&id, step),
        1,
        "idempotency key must prevent duplicate external resources for {}",
        step.as_str()
    );
    assert_eq!(
        ledger.calls_for(&id, step),
        2,
        "restart should retry the in-flight step once for {}",
        step.as_str()
    );
}

async fn crash_after_repository_save_does_not_reexecute_completed_step(
    step: WorkflowStepKind,
    index: usize,
) {
    let fake_clock = clock();
    let set = MemoryRepository::with_clock(fake_clock).into_set();
    let ledger = Arc::new(ExternalEffectLedger::default());
    let target: Arc<dyn StepExecutor> =
        Arc::new(IdempotentEffectExecutor::new(step, ledger.clone()));
    let engine = register_spine("after-save", set.clone(), Some(target));
    let id = submit(&set).await;

    drive_to_step(&engine, &set, &id, index).await;
    assert!(engine.run_step(&id).await.unwrap());
    let after_save = operation(&set, &id).await;
    assert!(
        after_save.steps[index].status == StepStatus::Completed
            || after_save.status == OperationStatus::Succeeded
    );
    drop(engine);

    let restarted = register_spine(
        "after-save-restart",
        set.clone(),
        Some(Arc::new(IdempotentEffectExecutor::new(
            step,
            ledger.clone(),
        ))),
    );
    assert_terminal_success(&restarted, &set, &id).await;
    assert_eq!(ledger.creations_for(&id, step), 1);
    assert_eq!(
        ledger.calls_for(&id, step),
        1,
        "completed step must not reexecute after restart for {}",
        step.as_str()
    );
}
