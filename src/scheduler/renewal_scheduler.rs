/// Advanced renewal scheduler with concurrency and priority support.
/// This module provides the `AdvancedRenewalScheduler` which manages a priority queue
/// of renewal tasks and executes them concurrently using a semaphore.
use crate::challenge::{ChallengeSolverRegistry, Http01Solver};
use crate::client::{AcmeClient, CertificateBundle};
use crate::error::Result;
use crate::renewal::RenewalHook;
use crate::storage::{CertificateStore, StorageBackend};
use std::collections::BinaryHeap;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify, mpsc};

/// Trait for renewal schedulers.
#[async_trait::async_trait]
pub trait RenewalScheduler: Send + Sync {
    /// Executes a single pass of the renewal check.
    async fn run_once(&self) -> Result<()>;
}

/// Priority levels for renewal tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Low priority (e.g., certificates expiring in > 15 days).
    Low = 0,
    /// Normal priority (e.g., certificates expiring in 7-15 days).
    Normal = 1,
    /// High priority (e.g., certificates expiring in < 7 days).
    High = 2,
    /// Urgent priority (e.g., certificates already expired or expiring in < 24 hours).
    Urgent = 3,
}

/// Represents a single certificate renewal task.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RenewalTask {
    /// The list of domains to renew.
    pub domains: Vec<String>,
    /// The priority of this task.
    pub priority: Priority,
    /// Number of times this task has been retried.
    pub retry_count: u32,
}

impl Ord for RenewalTask {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority tasks come first in the BinaryHeap
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for RenewalTask {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// An advanced scheduler that handles concurrent renewal tasks with priority.
#[derive(Clone)]
pub struct AdvancedRenewalScheduler<B: StorageBackend> {
    /// The ACME client used for issuance.
    client: AcmeClient,
    /// The store where certificates are persisted.
    store: CertificateStore<B>,
    /// Optional hooks for custom logic.
    hook: Option<Arc<dyn RenewalHook>>,
    /// Maximum number of concurrent renewal tasks.
    concurrency: usize,
    /// The priority queue of pending tasks.
    queue: Arc<Mutex<BinaryHeap<RenewalTask>>>,
    /// Notifier to wake up the scheduler when new tasks are added.
    notifier: Arc<Notify>,
    /// Channel sender for enqueuing new tasks.
    task_tx: mpsc::Sender<RenewalTask>,
}

impl<B: StorageBackend + 'static> AdvancedRenewalScheduler<B> {
    /// Creates a new `AdvancedRenewalScheduler` and returns the scheduler and a task sender.
    pub fn new(
        client: AcmeClient,
        store: CertificateStore<B>,
        concurrency: usize,
    ) -> (Self, TaskSender) {
        tracing::debug!("Initializing AdvancedRenewalScheduler with concurrency: {}", concurrency);
        let queue = Arc::new(Mutex::new(BinaryHeap::new()));
        let notifier = Arc::new(Notify::new());
        let (tx, mut rx) = mpsc::channel::<RenewalTask>(100);

        let q_clone = queue.clone();
        let n_clone = notifier.clone();

        // Background worker to bridge the channel and the priority heap
        tokio::spawn(async move {
            while let Some(task) = rx.recv().await {
                tracing::debug!("Enqueuing new renewal task for domains: {:?}", task.domains);
                q_clone.lock().await.push(task);
                n_clone.notify_waiters();
            }
        });

        let scheduler = Self {
            client,
            store,
            hook: None,
            concurrency,
            queue,
            notifier,
            task_tx: tx.clone(),
        };
        (scheduler, tx)
    }

    /// Sets a custom `RenewalHook`.
    pub fn with_hook(mut self, hook: Arc<dyn RenewalHook>) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Scans the storage and enqueues all certificates that require renewal.
    pub async fn run_once_internal(&self) -> Result<()> {
        tracing::info!("Scanning storage for certificates due for renewal");
        let certs = self.store.list_all().await?;
        for cert in certs {
            // In a real implementation, we would check the expiry here and set priority accordingly.
            // For now, we enqueue all found certificates with Normal priority.
            let _ = self
                .task_tx
                .send(RenewalTask {
                    domains: cert.domains.clone(),
                    priority: Priority::Normal,
                    retry_count: 0,
                })
                .await;
        }
        Ok(())
    }

    /// Starts the main scheduler loop.
    pub async fn run(self: Arc<Self>) {
        tracing::info!(
            "Starting Advanced Renewal Scheduler loop (Concurrency: {})",
            self.concurrency
        );
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrency));
        let scheduler_arc = self;

        loop {
            // Wait for tasks to become available in the queue
            {
                let q = scheduler_arc.queue.lock().await;
                if q.is_empty() {
                    drop(q);
                    tracing::debug!("Renewal queue empty, waiting for tasks...");
                    scheduler_arc.notifier.notified().await;
                    continue;
                }
            }

            // Acquire a concurrency permit
            let permit = semaphore.clone().acquire_owned().await.unwrap();

            // Pop the highest priority task
            let task = {
                let mut q = scheduler_arc.queue.lock().await;
                q.pop().unwrap()
            };

            let s = scheduler_arc.clone();
            tokio::spawn(async move {
                let _permit = permit; // Permit is released when this task finishes
                tracing::info!(
                    "Processing renewal task (Priority: {:?}) for domains: {:?}",
                    task.priority, task.domains
                );

                if let Some(h) = &s.hook {
                    h.before_renewal(&task.domains);
                }

                // Clone the client for thread-safe concurrent access
                let mut client = s.client.clone();
                match Self::perform_renewal(&mut client, &s.store, &task.domains).await {
                    Ok(bundle) => {
                        tracing::info!("Successfully renewed certificate for {:?}", task.domains);
                        if let Some(h) = &s.hook {
                            h.after_renewal(&task.domains, &bundle);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to renew certificate for {:?}: {}", task.domains, e);
                        if let Some(h) = &s.hook {
                            h.on_error(&task.domains, &e);
                        }

                        // Retry logic with a limit of 3 attempts
                        if task.retry_count < 3 {
                            let mut next_task = task.clone();
                            next_task.retry_count += 1;
                            tracing::warn!(
                                "Retrying renewal for {:?} (Attempt {}/3)",
                                task.domains, next_task.retry_count
                            );
                            let _ = s.task_tx.send(next_task).await;
                        } else {
                            tracing::error!("Maximum retries reached for domains: {:?}", task.domains);
                        }
                    }
                }
            });
        }
    }

    /// Internal helper to perform the actual certificate issuance.
    async fn perform_renewal(
        client: &mut AcmeClient,
        _store: &CertificateStore<B>,
        domains: &[String],
    ) -> Result<CertificateBundle> {
        let mut registry = ChallengeSolverRegistry::new();
        // Default to HTTP-01; in a full implementation, this would be configurable per task
        registry.register(Http01Solver::default());

        client
            .issue_certificate(domains.to_vec(), &mut registry)
            .await
    }
}

#[async_trait::async_trait]
impl<B: StorageBackend + 'static> RenewalScheduler for AdvancedRenewalScheduler<B> {
    async fn run_once(&self) -> Result<()> {
        self.run_once_internal().await
    }
}

/// Type alias for the task sender channel.
pub type TaskSender = mpsc::Sender<RenewalTask>;
