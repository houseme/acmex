use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use acmex::error::{AcmeError, Result};
use acmex::notifications::{OutboxConsumer, OutboxConsumerConfig, OutboxDelivery};
use acmex::repository::{FakeClock, LeaseOutcome, MemoryRepository, OutboxEvent};
use async_trait::async_trait;
use jiff::Timestamp;
use std::str::FromStr;

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
