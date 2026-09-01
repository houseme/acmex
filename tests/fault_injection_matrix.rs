use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use acmex::domain::{
    ClassifiedError, ErrorClass, OperationId, OperationKind, OperationRecord, OperationStatus,
    OperationSubject, WorkflowStepKind, error_codes,
};
use acmex::repository::{Clock, FakeClock, MemoryRepository, RepositorySet};
use acmex::workflow::{
    CompensationResult, FnStepExecutor, IssueWorkflow, StepResult, WorkflowEngine,
};
use jiff::Timestamp;

fn fixed_clock() -> Arc<FakeClock> {
    Arc::new(FakeClock::at(
        Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
    ))
}

fn set() -> RepositorySet {
    MemoryRepository::with_clock(fixed_clock()).into_set()
}

fn issue_engine(name: &str, set: RepositorySet) -> WorkflowEngine {
    let mut engine = WorkflowEngine::new(name, set);
    for executor in IssueWorkflow::skeleton() {
        engine.register(executor);
    }
    engine
}

async fn submit(set: &RepositorySet) -> OperationId {
    let id = OperationId::generate();
    set.operations
        .create(OperationRecord::new(
            id.clone(),
            OperationKind::Issue,
            OperationSubject::empty(),
            None,
            None,
            set.clock.now(),
        ))
        .await
        .unwrap();
    id
}

async fn get(set: &RepositorySet, id: &OperationId) -> OperationRecord {
    set.operations.get(id).await.unwrap().unwrap().value
}

#[tokio::test]
async fn ca_rate_limit_preserves_retry_after_and_does_not_sleep_task() {
    let fake_clock = fixed_clock();
    let set = MemoryRepository::with_clock(fake_clock.clone()).into_set();
    let mut engine = issue_engine("ca-429", set.clone());
    let retry_after = fake_clock
        .now()
        .checked_add(jiff::Span::new().minutes(10))
        .unwrap();
    engine.register(Arc::new(FnStepExecutor::new(
        WorkflowStepKind::FinalizeOrder,
        move |_| StepResult::RetryAt {
            after: Duration::from_secs(1),
            error: ClassifiedError {
                code: error_codes::ACME_RATE_LIMITED,
                class: ErrorClass::RateLimited {
                    retry_after: Some(retry_after),
                },
                detail: Some("fake CA 429".to_string()),
            },
        },
    )));
    let id = submit(&set).await;

    while get(&set, &id).await.current_step_index < 9 {
        assert!(engine.run_step(&id).await.unwrap());
    }
    assert!(engine.run_step(&id).await.unwrap());

    let record = get(&set, &id).await;
    assert_eq!(record.status, OperationStatus::Waiting);
    assert_eq!(record.wake_at, Some(retry_after));
}

#[tokio::test]
async fn transient_dns_cleanup_fault_retries_then_cancels_cleanly() {
    let fake_clock = fixed_clock();
    let set = MemoryRepository::with_clock(fake_clock.clone()).into_set();
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut engine = issue_engine("dns-cleanup", set.clone());
    engine.register(Arc::new(
        FnStepExecutor::new(WorkflowStepKind::PrepareChallenges, |_| {
            StepResult::complete_with_locator("dns://_acme-challenge.example.com/value")
        })
        .with_compensate({
            let attempts = attempts.clone();
            move |_| {
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    CompensationResult::RetryLater {
                        after: Duration::from_secs(1),
                        error: "fake provider 503".to_string(),
                    }
                } else {
                    CompensationResult::Done
                }
            }
        }),
    ));
    let id = submit(&set).await;

    while get(&set, &id).await.current_step_index <= 4 {
        assert!(engine.run_step(&id).await.unwrap());
    }
    assert!(engine.request_cancel(&id).await.unwrap());
    assert!(engine.run_step(&id).await.unwrap());
    assert_eq!(get(&set, &id).await.status, OperationStatus::Compensating);

    fake_clock.advance_secs(5);
    let done = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Cancelled);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn invalid_authorization_fails_with_operator_visible_classification() {
    let set = set();
    let mut engine = issue_engine("authz-invalid", set.clone());
    engine.register(Arc::new(FnStepExecutor::new(
        WorkflowStepKind::WaitAuthorizations,
        |_| {
            StepResult::Fail(ClassifiedError {
                code: error_codes::ACME_SERVER_ERROR,
                class: ErrorClass::Terminal,
                detail: Some("fake authorization invalid".to_string()),
            })
        },
    )));
    let id = submit(&set).await;

    let done = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Failed);
    assert_eq!(
        done.error.as_ref().unwrap().code,
        error_codes::ACME_SERVER_ERROR
    );
}
