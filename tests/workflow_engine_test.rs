//! Workflow engine behavior tests (roadmap T03): persistence granularity,
//! crash recovery, retry/backoff, Retry-After, cancel + compensation, and
//! multi-worker lease safety.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use acmex::domain::{
    ClassifiedError, ErrorClass, OperationId, OperationKind, OperationRecord, OperationStatus,
    OperationSubject, StepStatus, WorkflowStepKind, error_codes,
};
use acmex::repository::{Clock, FakeClock, MemoryRepository, RepositorySet};
use acmex::workflow::{
    CompensationResult, FnStepExecutor, IssueWorkflow, StepExecutor, StepResult, WorkflowEngine,
};
use jiff::Timestamp;

fn start_clock() -> Arc<FakeClock> {
    Arc::new(FakeClock::at(
        Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
    ))
}

fn engine(name: &str, set: RepositorySet) -> WorkflowEngine {
    let mut engine = WorkflowEngine::new(format!("worker-{name}"), set);
    for executor in IssueWorkflow::skeleton() {
        engine.register(executor);
    }
    engine
}

async fn submit(set: &RepositorySet, kind: OperationKind) -> OperationId {
    let id = OperationId::generate();
    let record = OperationRecord::new(
        id.clone(),
        kind,
        OperationSubject::empty(),
        None,
        None,
        set.clock.now(),
    );
    set.operations.create(record).await.unwrap();
    id
}

async fn get(set: &RepositorySet, id: &OperationId) -> OperationRecord {
    set.operations.get(id).await.unwrap().unwrap().value
}

// ---------------------------------------------------------------------------
// happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn skeleton_issuance_completes_and_emits_events() {
    let set = MemoryRepository::new().into_set();
    let engine = engine("a", set.clone());
    let id = engine
        .submit(OperationRecord::new(
            OperationId::generate(),
            OperationKind::Issue,
            OperationSubject::empty(),
            None,
            None,
            set.clock.now(),
        ))
        .await
        .unwrap();

    let final_record = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(final_record.status, OperationStatus::Succeeded);
    assert!(
        final_record
            .steps
            .iter()
            .all(|s| s.status == StepStatus::Completed)
    );

    // Outbox carries creation, per-step and terminal events.
    let events = set.outbox.list_pending(100).await.unwrap();
    let created = events.iter().any(|e| e.event_type == "operation.created");
    let step_events = events
        .iter()
        .filter(|e| e.event_type == "operation.step")
        .count();
    // The final step completes via the terminal transition (no separate
    // step event), so 16 step events + 1 finished event.
    assert!(step_events >= 16);
    let finished = events
        .iter()
        .any(|e| e.event_type == "operation.finished" && e.payload["status"] == "succeeded");
    assert!(created);
    assert!(finished);

    // Side-effect locators are persisted on the steps that made them.
    let prepare = final_record
        .steps
        .iter()
        .find(|s| s.kind == WorkflowStepKind::PrepareChallenges)
        .unwrap();
    assert_eq!(
        prepare.side_effect_locator.as_deref(),
        Some("skeleton://challenge")
    );
}

#[tokio::test]
async fn engine_records_operation_and_step_metrics() {
    let set = MemoryRepository::new().into_set();
    let metrics = Arc::new(acmex::metrics::MetricsRegistry::new());
    let engine = engine("metrics", set.clone()).with_metrics(metrics.clone());

    let id = engine
        .submit(OperationRecord::new(
            OperationId::generate(),
            OperationKind::Issue,
            OperationSubject::empty(),
            None,
            None,
            set.clock.now(),
        ))
        .await
        .unwrap();
    let final_record = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(final_record.status, OperationStatus::Succeeded);

    let text = metrics.gather_text();
    // Terminal outcome recorded with low-cardinality labels.
    assert!(
        text.contains(
            r#"acmex_operations_total{error_class="none",kind="issue",result="succeeded"} 1"#
        ),
        "missing operations_total series:\n{text}"
    );
    // Step durations observed (one histogram sample per executed step).
    let samples = text
        .lines()
        .filter(|line| {
            line.starts_with("acmex_operation_step_duration_seconds_count")
                && line.contains("result=\"completed\"")
        })
        .count();
    assert!(
        samples >= 17,
        "expected step duration series for the issuance spine, found {samples}:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// persistence granularity + crash recovery
// ---------------------------------------------------------------------------

/// A counting executor proves steps are never re-executed after a restart.
fn counting_set(kind: WorkflowStepKind, counter: Arc<AtomicUsize>) -> Arc<dyn StepExecutor> {
    Arc::new(FnStepExecutor::new(kind, move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        StepResult::done()
    }))
}

#[tokio::test]
async fn restart_does_not_reexecute_completed_steps() {
    let set = MemoryRepository::new().into_set();
    let finalize_calls = Arc::new(AtomicUsize::new(0));
    let verify_calls = Arc::new(AtomicUsize::new(0));
    // Executors are stateless and shared: a restarted process registers the
    // same executor implementations, so the counters observe real executions
    // across the restart boundary.
    let finalize_executor = counting_set(WorkflowStepKind::FinalizeOrder, finalize_calls.clone());
    let verify_executor = counting_set(WorkflowStepKind::VerifyCertificate, verify_calls.clone());

    {
        let mut first = engine("first", set.clone());
        first.register(finalize_executor.clone());
        first.register(verify_executor.clone());
        let id = submit(&set, OperationKind::Issue).await;
        // Advance exactly 10 steps, then "crash".
        for _ in 0..10 {
            assert!(first.run_step(&id).await.unwrap());
        }
        let record = get(&set, &id).await;
        assert_eq!(record.current_step_index, 10);
        assert_eq!(finalize_calls.load(Ordering::SeqCst), 1);
    }

    // New engine instance (fresh in-memory process) resumes.
    let mut second = engine("second", set.clone());
    second.register(finalize_executor);
    second.register(verify_executor);
    let id_back = {
        let ops = set
            .operations
            .list_by_status(OperationStatus::Running, 10)
            .await
            .unwrap();
        ops[0].value.id.clone()
    };
    let done = second
        .run_until_terminal(&id_back, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Succeeded);
    // Neither already-completed step ran again.
    assert_eq!(finalize_calls.load(Ordering::SeqCst), 1);
    assert_eq!(verify_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn one_run_step_advances_exactly_one_step() {
    let set = MemoryRepository::new().into_set();
    let engine = engine("single", set.clone());
    let id = submit(&set, OperationKind::Issue).await;

    for expected in 0..5 {
        assert!(engine.run_step(&id).await.unwrap());
        let record = get(&set, &id).await;
        assert_eq!(record.current_step_index, expected + 1);
        assert!(record.steps[expected].status == StepStatus::Completed);
    }
}

// ---------------------------------------------------------------------------
// retry / backoff / Retry-After / terminal failure
// ---------------------------------------------------------------------------

fn classified(class: ErrorClass) -> ClassifiedError {
    ClassifiedError {
        code: error_codes::ACME_SERVER_ERROR,
        class,
        detail: None,
    }
}

#[tokio::test]
async fn retryable_step_retries_then_completes() {
    let clock = start_clock();
    let set = MemoryRepository::with_clock(clock.clone()).into_set();
    let mut engine = WorkflowEngine::new("retry", set.clone());
    for executor in IssueWorkflow::skeleton() {
        engine.register(executor);
    }
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    engine.register(Arc::new(FnStepExecutor::new(
        WorkflowStepKind::FinalizeOrder,
        move |_| {
            if counter.fetch_add(1, Ordering::SeqCst) < 2 {
                StepResult::RetryAt {
                    after: Duration::from_secs(1),
                    error: classified(ErrorClass::Retryable),
                }
            } else {
                StepResult::done()
            }
        },
    )));

    let id = submit(&set, OperationKind::Issue).await;
    // Run all steps until Finalize fails retryably.
    while get(&set, &id).await.current_step_index < 9 {
        engine.run_step(&id).await.unwrap();
    }
    engine.run_step(&id).await.unwrap(); // attempt 1 -> retry scheduled
    let record = get(&set, &id).await;
    assert_eq!(record.status, OperationStatus::Waiting);
    assert!(
        record.wake_at.is_some(),
        "retry schedules a wake_at, never a sleeping task"
    );
    assert_eq!(record.steps[9].attempt, 1);
    assert_eq!(record.steps[9].status, StepStatus::Failed);

    clock.advance_secs(5); // past backoff
    engine.run_step(&id).await.unwrap(); // attempt 2 -> retry
    let record = get(&set, &id).await;
    assert_eq!(record.steps[9].attempt, 2);

    clock.advance_secs(10);
    let done = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Succeeded);
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn retry_after_overrides_local_backoff() {
    let clock = start_clock();
    let set = MemoryRepository::with_clock(clock.clone()).into_set();
    let mut engine = WorkflowEngine::new("rate", set.clone());
    for executor in IssueWorkflow::skeleton() {
        engine.register(executor);
    }
    let retry_after = clock
        .now()
        .checked_add(jiff::Span::new().minutes(42))
        .unwrap();
    engine.register(Arc::new(FnStepExecutor::new(
        WorkflowStepKind::EnsureAccount,
        move |_| StepResult::RetryAt {
            after: Duration::from_secs(1),
            error: ClassifiedError {
                code: error_codes::ACME_RATE_LIMITED,
                class: ErrorClass::RateLimited {
                    retry_after: Some(retry_after),
                },
                detail: None,
            },
        },
    )));

    let id = submit(&set, OperationKind::Issue).await;
    engine.run_step(&id).await.unwrap(); // Plan
    engine.run_step(&id).await.unwrap(); // EnsureAccount -> rate limited
    let record = get(&set, &id).await;
    assert_eq!(
        record.wake_at,
        Some(retry_after),
        "CA Retry-After must win over local backoff"
    );
}

#[tokio::test]
async fn exhausted_retries_fail_the_operation() {
    let set = MemoryRepository::new().into_set();
    let mut engine =
        WorkflowEngine::new("fail", set.clone()).with_config(acmex::workflow::EngineConfig {
            retry_backoff_base: Duration::from_millis(1),
            retry_backoff_max: Duration::from_millis(5),
            ..Default::default()
        });
    for executor in IssueWorkflow::skeleton() {
        engine.register(executor);
    }
    engine.register(Arc::new(FnStepExecutor::new(
        WorkflowStepKind::DownloadCertificate,
        move |_| StepResult::RetryAt {
            after: Duration::from_millis(1),
            error: classified(ErrorClass::Retryable),
        },
    )));

    let id = submit(&set, OperationKind::Issue).await;
    let done = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Failed);
    assert_eq!(
        done.error.as_ref().unwrap().code,
        error_codes::ACME_SERVER_ERROR
    );
    assert_eq!(
        done.steps
            .iter()
            .find(|s| s.kind == WorkflowStepKind::DownloadCertificate)
            .unwrap()
            .attempt,
        3,
        "default budget is three attempts"
    );
}

#[tokio::test]
async fn terminal_step_failure_fails_immediately() {
    let set = MemoryRepository::new().into_set();
    let mut engine = WorkflowEngine::new("policy", set.clone());
    for executor in IssueWorkflow::skeleton() {
        engine.register(executor);
    }
    engine.register(Arc::new(FnStepExecutor::new(
        WorkflowStepKind::Plan,
        move |_| {
            StepResult::Fail(ClassifiedError {
                code: error_codes::VALIDATION_CHALLENGE_INCOMPATIBLE,
                class: ErrorClass::PolicyViolation,
                detail: Some("ip identifiers cannot use dns-01".to_string()),
            })
        },
    )));

    let id = submit(&set, OperationKind::Issue).await;
    let done = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Failed);
    let error = done.error.unwrap();
    assert_eq!(error.code, error_codes::VALIDATION_CHALLENGE_INCOMPATIBLE);
    assert_eq!(
        error.detail.as_deref(),
        Some("ip identifiers cannot use dns-01")
    );
}

// ---------------------------------------------------------------------------
// cancel + compensation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancel_runs_pending_compensations_then_cancels() {
    let set = MemoryRepository::new().into_set();
    let engine = engine("cancel", set.clone());
    let id = submit(&set, OperationKind::Issue).await;

    // Advance past PrepareChallenges (compensation pending) and stop.
    while get(&set, &id).await.current_step_index <= 4 {
        engine.run_step(&id).await.unwrap();
    }
    let record = get(&set, &id).await;
    let prepare = record
        .steps
        .iter()
        .find(|s| s.kind == WorkflowStepKind::PrepareChallenges)
        .unwrap();
    assert_eq!(
        prepare.compensation,
        acmex::domain::CompensationState::Pending
    );

    // Cancel while later steps are still pending.
    assert!(engine.request_cancel(&id).await.unwrap());
    assert_eq!(
        get(&set, &id).await.status,
        OperationStatus::CancelRequested
    );

    let done = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Cancelled);
    let prepare = done
        .steps
        .iter()
        .find(|s| s.kind == WorkflowStepKind::PrepareChallenges)
        .unwrap();
    assert_eq!(prepare.compensation, acmex::domain::CompensationState::Done);
    // Steps after the cancellation point never ran.
    let later = done
        .steps
        .iter()
        .find(|s| s.kind == WorkflowStepKind::Complete)
        .unwrap();
    assert_eq!(later.status, StepStatus::Pending);
}

#[tokio::test]
async fn compensation_retries_then_succeeds() {
    let clock = start_clock();
    let set = MemoryRepository::with_clock(clock.clone()).into_set();
    let mut engine = WorkflowEngine::new("cleanup-retry", set.clone());
    for executor in IssueWorkflow::skeleton() {
        engine.register(executor);
    }
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    engine.register(Arc::new(
        FnStepExecutor::new(WorkflowStepKind::PrepareChallenges, move |_| {
            StepResult::complete_with_locator("dns://record-1")
        })
        .with_compensate(move |_| {
            if counter.fetch_add(1, Ordering::SeqCst) < 2 {
                CompensationResult::RetryLater {
                    after: Duration::from_secs(1),
                    error: "provider 503".to_string(),
                }
            } else {
                CompensationResult::Done
            }
        }),
    ));

    let id = submit(&set, OperationKind::Issue).await;
    while get(&set, &id).await.current_step_index <= 4 {
        engine.run_step(&id).await.unwrap();
    }
    engine.request_cancel(&id).await.unwrap();
    engine.run_step(&id).await.unwrap(); // first compensation pass: retry later
    let record = get(&set, &id).await;
    assert_eq!(record.status, OperationStatus::Compensating);
    assert!(record.wake_at.is_some());

    clock.advance_secs(5);
    engine.run_step(&id).await.unwrap(); // second pass: retry later
    clock.advance_secs(5);
    let done = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Cancelled);
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn compensation_exhaustion_reports_compensation_failed() {
    let set = MemoryRepository::new().into_set();
    let mut engine = WorkflowEngine::new("cleanup-fail", set.clone());
    for executor in IssueWorkflow::skeleton() {
        engine.register(executor);
    }
    engine.register(Arc::new(
        FnStepExecutor::new(WorkflowStepKind::PrepareChallenges, move |_| {
            StepResult::complete_with_locator("dns://record-1")
        })
        .with_compensate(|_| CompensationResult::RetryLater {
            after: Duration::from_millis(1),
            error: "provider down".to_string(),
        }),
    ));

    let id = submit(&set, OperationKind::Issue).await;
    while get(&set, &id).await.current_step_index <= 4 {
        engine.run_step(&id).await.unwrap();
    }
    engine.request_cancel(&id).await.unwrap();
    let done = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::CompensationFailed);
    assert_eq!(
        done.error.as_ref().unwrap().code,
        error_codes::CHALLENGE_CLEANUP_FAILED
    );
    let prepare = done
        .steps
        .iter()
        .find(|s| s.kind == WorkflowStepKind::PrepareChallenges)
        .unwrap();
    assert_eq!(
        prepare.compensation,
        acmex::domain::CompensationState::Failed
    );
    assert_eq!(prepare.compensation_attempts, 3);
}

// ---------------------------------------------------------------------------
// concurrency: leases, double workers, cancel races
// ---------------------------------------------------------------------------

#[tokio::test]
async fn held_lease_skips_operation() {
    let set = MemoryRepository::new().into_set();
    let engine = engine("b", set.clone());
    let id = submit(&set, OperationKind::Issue).await;

    // Another worker holds the lease.
    set.leases
        .acquire(
            &format!("op/{}", id.as_str()),
            "someone-else",
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    assert!(
        !engine.run_step(&id).await.unwrap(),
        "leased operation is skipped"
    );
    assert_eq!(get(&set, &id).await.current_step_index, 0);
}

#[tokio::test]
async fn two_workers_advance_consistently() {
    let set = MemoryRepository::new().into_set();
    let engine_a = engine("a", set.clone());
    let engine_b = engine("b", set.clone());
    let id = submit(&set, OperationKind::Issue).await;

    // Both workers race for the same operation repeatedly; the lease
    // serializes them and CAS protects the persisted state.
    let mut rounds = 0;
    loop {
        let record = get(&set, &id).await;
        if record.status.is_terminal() {
            break;
        }
        let (a, b) = tokio::join!(async { engine_a.run_step(&id).await.unwrap() }, async {
            engine_b.run_step(&id).await.unwrap()
        });
        assert!(a || b, "at least one worker must advance a ready operation");
        rounds += 1;
        assert!(rounds < 100, "workers stopped advancing");
    }
    let record = get(&set, &id).await;
    assert_eq!(record.status, OperationStatus::Succeeded);
    // Every step completed exactly once (attempts stay at 1).
    assert!(record.steps.iter().all(|s| s.attempt == 1));
}

#[tokio::test]
async fn cancel_before_any_step_cancels_without_side_effects() {
    let set = MemoryRepository::new().into_set();
    let engine = engine("early", set.clone());
    let id = submit(&set, OperationKind::Issue).await;

    engine.request_cancel(&id).await.unwrap();
    let done = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Cancelled);
    // Nothing executed.
    assert!(done.steps.iter().all(|s| s.status == StepStatus::Pending));
}

// ---------------------------------------------------------------------------
// file backend compatibility (restart across processes)
// ---------------------------------------------------------------------------

struct TempDir {
    path: std::path::PathBuf,
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn temp_dir(label: &str) -> TempDir {
    let path = std::env::temp_dir().join(format!(
        "acmex-wf-{label}-{}-{}",
        std::process::id(),
        acmex::repository::SystemClock.now().as_millisecond()
    ));
    std::fs::create_dir_all(&path).expect("temp dir");
    TempDir { path }
}

#[tokio::test]
async fn file_backend_resumes_after_engine_recreation() {
    let dir = temp_dir("resume");
    let set = acmex::repository::FileRepository::new(&dir.path)
        .await
        .unwrap()
        .into_set();
    let id = {
        let engine = engine("p1", set.clone());
        let id = submit(&set, OperationKind::Issue).await;
        for _ in 0..6 {
            engine.run_step(&id).await.unwrap();
        }
        id
    };

    // Completely new engine instance over the same directory.
    let engine = engine("p2", set.clone());
    let done = engine
        .run_until_terminal(&id, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Succeeded);
    assert!(done.steps.iter().all(|s| s.status == StepStatus::Completed));
    assert!(done.steps.iter().all(|s| s.attempt == 1));
}

/// Two engines sharing the file repository: consistent single advancement.
#[tokio::test]
async fn file_backend_two_workers_consistent() {
    let dir = temp_dir("twofile");
    let set = acmex::repository::FileRepository::new(&dir.path)
        .await
        .unwrap()
        .into_set();
    let a = engine("fa", set.clone());
    let b = engine("fb", set.clone());
    let id = submit(&set, OperationKind::Issue).await;

    for _ in 0..17 {
        let (ra, rb) = tokio::join!(async { a.run_step(&id).await.unwrap() }, async {
            b.run_step(&id).await.unwrap()
        });
        assert!(ra || rb);
    }
    let record = get(&set, &id).await;
    assert_eq!(record.status, OperationStatus::Succeeded);
    assert!(record.steps.iter().all(|s| s.attempt == 1));
}

// ---------------------------------------------------------------------------
// repository failure metrics (T11)
// ---------------------------------------------------------------------------

/// Repository failures on the file backend must surface through the
/// repository decorator as `acmex_repository_errors_total{backend,operation}`.
///
/// `FileRepository::new` creates its aggregate directories eagerly, so the
/// failure is forced after construction: the `operations` aggregate
/// directory is replaced by a regular file, making every list/read fail.
#[tokio::test]
async fn file_backend_repository_failures_increment_repository_errors_total() {
    let dir = temp_dir("repo-err");
    let set = acmex::repository::FileRepository::new(&dir.path)
        .await
        .unwrap()
        .into_set();
    std::fs::remove_dir_all(dir.path.join("operations")).expect("remove operations dir");
    std::fs::write(dir.path.join("operations"), b"blocked").expect("block operations dir");

    let metrics = Arc::new(acmex::metrics::MetricsRegistry::new());
    let engine = engine("repo-err", set.clone()).with_metrics(metrics.clone());

    // run_once fails at list_ready…
    assert!(engine.run_once().await.is_err());
    // …and run_step fails at the operation load; both are repository
    // failures, not step failures.
    assert!(engine.run_step(&OperationId::generate()).await.is_err());

    let text = metrics.gather_text();
    let line = text
        .lines()
        .find(|l| {
            l.starts_with(r#"acmex_repository_errors_total{backend="file""#)
                && l.contains(r#"operation="scan""#)
        })
        .unwrap_or_else(|| panic!("missing repository_errors_total series:\n{text}"));
    assert!(
        !line.contains("error_class"),
        "repository error labels must be backend+operation only: {line}"
    );
    let value: u64 = line
        .rsplit(' ')
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("malformed metric line: {line}"));
    assert!(value >= 1, "expected at least one repository error: {line}");
}

// ---------------------------------------------------------------------------
// registry completeness
// ---------------------------------------------------------------------------

#[test]
fn skeleton_covers_every_spine_step() {
    let executors = IssueWorkflow::skeleton();
    let mut kinds: Vec<_> = executors.iter().map(|e| e.kind()).collect();
    kinds.sort_by_key(|k| format!("{k:?}"));
    let mut spine: Vec<_> = WorkflowStepKind::issuance_spine().to_vec();
    spine.sort_by_key(|k| format!("{k:?}"));
    assert_eq!(kinds, spine);
}

#[tokio::test]
async fn missing_executor_is_terminal_internal_error() {
    let set = MemoryRepository::new().into_set();
    let engine = WorkflowEngine::new("bare", set.clone()); // no executors
    let id = submit(&set, OperationKind::Issue).await;
    let done = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Failed);
    assert_eq!(done.error.as_ref().unwrap().code, error_codes::INTERNAL);
}

/// Overrides replace exactly one skeleton step.
#[tokio::test]
async fn skeleton_overrides_replace_single_step() {
    let set = MemoryRepository::new().into_set();
    let mut engine = WorkflowEngine::new("ovr", set.clone());
    let mut overrides: HashMap<WorkflowStepKind, Arc<dyn StepExecutor>> = HashMap::new();
    overrides.insert(
        WorkflowStepKind::VerifyCertificate,
        Arc::new(FnStepExecutor::new(
            WorkflowStepKind::VerifyCertificate,
            |_| {
                StepResult::Fail(ClassifiedError {
                    code: error_codes::INTERNAL,
                    class: ErrorClass::Terminal,
                    detail: Some("certificate mismatch".to_string()),
                })
            },
        )),
    );
    for executor in IssueWorkflow::skeleton_with_overrides(overrides) {
        engine.register(executor);
    }
    let id = submit(&set, OperationKind::Issue).await;
    let done = engine
        .run_until_terminal(&id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, OperationStatus::Failed);
    assert_eq!(
        done.error.as_ref().unwrap().detail.as_deref(),
        Some("certificate mismatch")
    );
}

// ---------------------------------------------------------------------------
// trace span convention (T11, docs/SECURITY_OBSERVABILITY_HA.md)
// ---------------------------------------------------------------------------

/// Collects the fields of a newly created span (`tracing::field::Visit`).
///
/// The engine records convention values with `tracing::field::display`,
/// which surfaces through `record_debug`.
#[derive(Default)]
struct FieldCollector(Vec<(&'static str, String)>);

impl tracing::field::Visit for FieldCollector {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name(), format!("{value:?}")));
    }
}

/// A `tracing` layer capturing `workflow.*` spans and their fields.
///
/// Fields recorded later (the engine declares optional subject fields as
/// `field::Empty` and fills them via `Span::record`) arrive through
/// `on_record`, so both hooks merge into one entry per span id.
///
/// Uses only `tracing`/`tracing-subscriber` (already dependencies), so no
/// tracing test-capture dev-dependency is required.
#[derive(Clone, Default)]
#[allow(clippy::type_complexity)] // one-off test capture: (span id, name, fields)
struct SpanCapture {
    spans: std::sync::Arc<
        std::sync::Mutex<Vec<(tracing::span::Id, &'static str, Vec<(&'static str, String)>)>>,
    >,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanCapture {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let name = attrs.metadata().name();
        if name != "workflow.operation" && name != "workflow.step" {
            return;
        }
        let mut fields = FieldCollector::default();
        attrs.record(&mut fields);
        self.spans
            .lock()
            .unwrap()
            .push((id.clone(), name, fields.0));
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut spans = self.spans.lock().unwrap();
        let Some((_, _, fields)) = spans.iter_mut().find(|(span_id, _, _)| span_id == id) else {
            return;
        };
        let mut recorded = FieldCollector::default();
        values.record(&mut recorded);
        for (key, value) in recorded.0 {
            match fields.iter_mut().find(|(existing, _)| *existing == key) {
                Some(slot) => slot.1 = value,
                None => fields.push((key, value)),
            }
        }
    }
}

impl SpanCapture {
    /// Fields of the first span with `span_name` whose `operation_id` field
    /// equals `operation_id`.
    ///
    /// Filtering by operation_id matters because the capture subscriber is
    /// installed process-wide: under parallel test execution other tests'
    /// engine spans flow into the same capture.
    fn fields_of(&self, span_name: &str, operation_id: &str) -> Vec<(&'static str, String)> {
        self.spans
            .lock()
            .unwrap()
            .iter()
            .find(|(_, name, fields)| {
                *name == span_name
                    && fields
                        .iter()
                        .any(|(key, value)| *key == "operation_id" && value == operation_id)
            })
            .map(|(_, _, fields)| fields.clone())
            .unwrap_or_default()
    }
}

fn field_value<'a>(fields: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.as_str())
}

/// One engine step must emit `workflow.operation` and `workflow.step`
/// spans carrying the trace-convention fields that exist on the record
/// (operation_id, kind, workflow_step, intent_id, lineage_id — and not
/// values that do not, like version_id here).
#[tokio::test]
async fn engine_steps_emit_convention_trace_fields() {
    let set = MemoryRepository::new().into_set();
    let engine = engine("trace", set.clone());
    let subject = OperationSubject {
        intent_id: Some(acmex::domain::IntentId::generate()),
        lineage_id: Some(acmex::domain::LineageId::generate()),
        version_id: None,
    };
    let id = OperationId::generate();
    set.operations
        .create(OperationRecord::new(
            id.clone(),
            OperationKind::Issue,
            subject,
            None,
            None,
            set.clock.now(),
        ))
        .await
        .unwrap();

    let capture = SpanCapture::default();
    use tracing_subscriber::prelude::*;
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    // Global (not thread-local) default on purpose: this binary's other
    // tests also run the engine, and their first use of the shared
    // `workflow.*` span callsites against a no-op default would cache
    // `Interest::never` process-wide, disabling the spans on this thread
    // as well. A global install keeps the interest cache enabled; entries
    // are then filtered by operation_id below.
    tracing::subscriber::set_global_default(subscriber).expect("install span capture subscriber");

    assert!(engine.run_step(&id).await.unwrap());

    // Operation-level span.
    let operation = capture.fields_of("workflow.operation", id.as_str());
    assert!(
        !operation.is_empty(),
        "workflow.operation span must be emitted"
    );
    assert_eq!(field_value(&operation, "operation_id"), Some(id.as_str()));
    assert_eq!(field_value(&operation, "kind"), Some("issue"));
    let intent_id = field_value(&operation, "intent_id")
        .expect("intent_id exists on the subject and must be recorded")
        .to_string();
    let lineage_id = field_value(&operation, "lineage_id")
        .expect("lineage_id exists on the subject and must be recorded")
        .to_string();
    assert!(intent_id.starts_with("int_"), "{intent_id}");
    assert!(lineage_id.starts_with("lin_"), "{lineage_id}");
    assert!(
        field_value(&operation, "version_id").is_none(),
        "version_id does not exist on this subject and must stay unrecorded"
    );

    // Step-level span: the first spine step is `plan`.
    let step = capture.fields_of("workflow.step", id.as_str());
    assert!(!step.is_empty(), "workflow.step span must be emitted");
    assert_eq!(field_value(&step, "operation_id"), Some(id.as_str()));
    assert_eq!(field_value(&step, "workflow_step"), Some("plan"));
    assert_eq!(field_value(&step, "kind"), Some("issue"));
    assert_eq!(field_value(&step, "intent_id"), Some(intent_id.as_str()));
    assert_eq!(field_value(&step, "lineage_id"), Some(lineage_id.as_str()));
    for fields in [&operation, &step] {
        assert!(field_value(fields, "identifier").is_none());
        assert!(field_value(fields, "token").is_none());
        assert!(field_value(fields, "key_authorization").is_none());
        assert!(
            fields.iter().all(|(_, value)| {
                !value.contains("example.com")
                    && !value.contains("-----BEGIN")
                    && !value.to_ascii_lowercase().contains("token")
            }),
            "trace fields must not expose identifiers or secrets: {fields:?}"
        );
    }
}
