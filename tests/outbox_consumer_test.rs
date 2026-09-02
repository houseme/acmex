use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use acmex::error::{AcmeError, Result};
use acmex::notifications::{
    EventType, OutboxConsumer, OutboxConsumerConfig, OutboxDelivery, WebhookConfig, WebhookFormat,
    WebhookManager, verify_webhook_signature,
};
use acmex::repository::{FakeClock, FileRepository, LeaseOutcome, MemoryRepository, OutboxEvent};
use async_trait::async_trait;
use jiff::Timestamp;
use std::str::FromStr;

/// The headers+body captured by the signing endpoint.
type CapturedRequest =
    std::sync::Arc<std::sync::Mutex<Option<(reqwest::header::HeaderMap, Vec<u8>)>>>;

#[derive(Default)]
struct CountingDelivery {
    calls: AtomicUsize,
    fail_first: usize,
}

#[async_trait]
impl OutboxDelivery for CountingDelivery {
    async fn deliver(&self, _event: &OutboxEvent) -> Result<()> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call <= self.fail_first {
            Err(AcmeError::transport("webhook 500"))
        } else {
            Ok(())
        }
    }
}

fn config(owner: &str) -> OutboxConsumerConfig {
    OutboxConsumerConfig {
        owner: owner.to_string(),
        lease_ttl: Duration::from_secs(30),
        batch_size: 16,
        max_attempts: 2,
        retry_backoff_base: Duration::from_secs(5),
        retry_backoff_max: Duration::from_secs(30),
    }
}

#[tokio::test]
async fn outbox_consumer_delivers_and_marks_processed() {
    let set = MemoryRepository::new().into_set();
    set.outbox
        .append(
            "operation.finished",
            serde_json::json!({"operation_id": "op_1"}),
            None,
        )
        .await
        .unwrap();
    let delivery = Arc::new(CountingDelivery::default());
    let consumer = OutboxConsumer::new(set.clone(), delivery.clone(), config("consumer-a"));

    let report = consumer.run_once().await.unwrap();
    assert_eq!(report.delivered, 1);
    assert_eq!(delivery.calls.load(Ordering::SeqCst), 1);
    assert!(set.outbox.list_pending(10).await.unwrap().is_empty());
}

#[tokio::test]
async fn outbox_consumer_retries_then_dead_letters_and_requeues() {
    let clock = Arc::new(FakeClock::at(
        Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
    ));
    let set = MemoryRepository::with_clock(clock.clone()).into_set();
    let seq = set
        .outbox
        .append(
            "operation.finished",
            serde_json::json!({"operation_id": "op_1"}),
            None,
        )
        .await
        .unwrap();
    let delivery = Arc::new(CountingDelivery {
        calls: AtomicUsize::new(0),
        fail_first: 2,
    });
    let consumer = OutboxConsumer::new(set.clone(), delivery, config("consumer-a"));

    let first = consumer.run_once().await.unwrap();
    assert_eq!(first.failed, 1);
    assert!(set.outbox.list_pending(10).await.unwrap().is_empty());

    clock.advance_secs(6);
    let second = consumer.run_once().await.unwrap();
    assert_eq!(second.dead_lettered, 1);
    assert!(set.outbox.list_pending(10).await.unwrap().is_empty());

    set.outbox.requeue(seq).await.unwrap();
    assert_eq!(set.outbox.list_pending(10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn outbox_consumer_lease_fencing_prevents_duplicate_delivery() {
    let set = MemoryRepository::new().into_set();
    let seq = set
        .outbox
        .append(
            "operation.finished",
            serde_json::json!({"operation_id": "op_1"}),
            None,
        )
        .await
        .unwrap();
    let _held = match set
        .leases
        .acquire(
            &format!("outbox/{seq}"),
            "consumer-a",
            Duration::from_secs(30),
        )
        .await
        .unwrap()
    {
        LeaseOutcome::Granted(grant) => grant,
        other => panic!("expected lease grant, got {other:?}"),
    };
    let delivery = Arc::new(CountingDelivery::default());
    let consumer = OutboxConsumer::new(set.clone(), delivery.clone(), config("consumer-b"));

    let report = consumer.run_once().await.unwrap();
    assert_eq!(report.leased_elsewhere, 1);
    assert_eq!(delivery.calls.load(Ordering::SeqCst), 0);
    assert_eq!(set.outbox.list_pending(10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn outbox_consumer_tracks_pending_backlog_per_event_type() {
    let set = MemoryRepository::new().into_set();
    set.outbox
        .append(
            "operation.finished",
            serde_json::json!({"operation_id": "op_1"}),
            None,
        )
        .await
        .unwrap();
    set.outbox
        .append(
            "operation.finished",
            serde_json::json!({"operation_id": "op_2"}),
            None,
        )
        .await
        .unwrap();
    set.outbox
        .append(
            "deployment.scheduled",
            serde_json::json!({"deployment_id": "dep_1"}),
            None,
        )
        .await
        .unwrap();

    let delivery = Arc::new(CountingDelivery {
        calls: AtomicUsize::new(0),
        fail_first: 1, // first event fails once and stays pending
    });
    let metrics = Arc::new(acmex::metrics::MetricsRegistry::new());
    let consumer = OutboxConsumer::new(set.clone(), delivery.clone(), config("consumer-a"))
        .with_metrics(metrics.clone());

    let report = consumer.run_once().await.unwrap();
    assert_eq!(report.delivered + report.failed, 3);
    assert_eq!(delivery.calls.load(Ordering::SeqCst), 3);

    let text = metrics.gather_text();
    // The gauge series exists per event type seen…
    assert!(
        text.contains(r#"acmex_outbox_pending{event_type="operation.finished"}"#),
        "{text}"
    );
    assert!(
        text.contains(r#"acmex_outbox_pending{event_type="deployment.scheduled"}"#),
        "{text}"
    );
    // …and everything except the failed event drained back to zero.
    assert!(
        text.contains(r#"acmex_outbox_pending{event_type="deployment.scheduled"} 0"#),
        "{text}"
    );
    let failed_backlog = text
        .lines()
        .find(|line| line.starts_with(r#"acmex_outbox_pending{event_type="operation.finished""#))
        .unwrap();
    assert!(
        failed_backlog.ends_with(" 1"),
        "the failed event must stay pending: {failed_backlog}"
    );
}

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
        "acmex-outbox-{label}-{}-{}",
        std::process::id(),
        jiff::Timestamp::now().as_millisecond()
    ));
    std::fs::create_dir_all(&path).expect("temp dir");
    TempDir { path }
}

/// Repository failures (not delivery failures) must surface as
/// `acmex_repository_errors_total{backend="file",...}`.
///
/// The `outbox` aggregate directory is replaced by a regular file so
/// `list_pending` fails before any delivery is attempted.
#[tokio::test]
async fn outbox_consumer_counts_repository_errors_not_delivery_errors() {
    let dir = temp_dir("repo-err");
    let set = FileRepository::new(&dir.path).await.unwrap().into_set();
    std::fs::remove_dir_all(dir.path.join("outbox")).expect("remove outbox dir");
    std::fs::write(dir.path.join("outbox"), b"blocked").expect("block outbox dir");

    let delivery = Arc::new(CountingDelivery::default());
    let metrics = Arc::new(acmex::metrics::MetricsRegistry::new());
    let consumer = OutboxConsumer::new(set.clone(), delivery.clone(), config("consumer-err"))
        .with_metrics(metrics.clone());

    assert!(consumer.run_once().await.is_err());
    // The failure happened in the repository: delivery was never invoked.
    assert_eq!(delivery.calls.load(Ordering::SeqCst), 0);

    let text = metrics.gather_text();
    let line = text
        .lines()
        .find(|l| l.starts_with(r#"acmex_repository_errors_total{backend="file""#))
        .unwrap_or_else(|| panic!("missing repository_errors_total series:\n{text}"));
    assert!(
        line.contains(r#"error_class="storage""#),
        "unexpected error class: {line}"
    );
    assert!(
        line.ends_with(" 1"),
        "expected exactly one repository error: {line}"
    );
}

// ---------------------------------------------------------------------------
// signed webhook delivery end-to-end (T11)
// ---------------------------------------------------------------------------

/// Captures one received webhook request (headers + raw body).
#[derive(Clone, Default)]
struct WebhookCapture {
    inner: CapturedRequest,
}

/// End-to-end proof that sender output verifies with the consumer helper:
/// a `WebhookManager` delivery (HMAC headers added by `WebhookClient`)
/// must pass `verify_webhook_signature` with the shared secret, and the
/// returned event id must match the delivered outbox event.
#[tokio::test]
async fn signed_webhook_delivery_verifies_consumer_side() {
    use axum::extract::State;
    use axum::http::StatusCode;

    const SECRET: &str = "whsec_roundtrip";

    async fn capture_hook(
        State(capture): State<WebhookCapture>,
        headers: reqwest::header::HeaderMap,
        body: axum::body::Bytes,
    ) -> StatusCode {
        *capture.inner.lock().unwrap() = Some((headers, body.to_vec()));
        StatusCode::OK
    }

    // A real HTTP endpoint that records what the sender produced.
    let capture = WebhookCapture::default();
    let app = axum::Router::new()
        .route("/hook", axum::routing::post(capture_hook))
        .with_state(capture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // The signing secret comes from a file via the built-in resolver.
    let dir = temp_dir("sign-roundtrip");
    let secret_path = dir.path.join("webhook-signing-secret");
    std::fs::write(&secret_path, SECRET).expect("write secret file");

    let manager = WebhookManager::new(vec![WebhookConfig {
        name: "roundtrip".to_string(),
        url: format!("http://{addr}/hook"),
        events: vec![EventType::CertificateObtained],
        format: WebhookFormat::Json,
        auth_token: None,
        signing_secret: Some(acmex::dns::spec::SecretRef::File {
            path: secret_path.clone(),
        }),
        timeout_secs: 5,
        max_retries: 1,
    }]);

    let event = OutboxEvent {
        sequence: 1,
        event_id: "evt_roundtrip".to_string(),
        event_type: "operation.finished".to_string(),
        payload: serde_json::json!({"operation_id": "op_1", "status": "succeeded"}),
        created_at: Timestamp::now(),
        attempts: 0,
        last_error: None,
        next_attempt_at: None,
        processed: false,
        dead_lettered: false,
    };
    manager.deliver(&event).await.unwrap();

    let (headers, body) = capture
        .inner
        .lock()
        .unwrap()
        .take()
        .expect("webhook endpoint captured the delivery");
    let verified =
        verify_webhook_signature(&headers, &body, SECRET.as_bytes(), Duration::from_secs(300))
            .expect("sender signature must verify with the shared secret");
    assert_eq!(verified, "evt_roundtrip");
}
