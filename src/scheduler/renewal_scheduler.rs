use crate::challenge::{ChallengeSolverRegistry, Http01Solver};
use crate::client::{AcmeClient, CertificateBundle};
use crate::error::Result;
use crate::renewal::RenewalHook;
use crate::storage::{CertificateStore, StorageBackend};
use std::collections::BinaryHeap;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify, mpsc};
use tracing::{error, info, warn};

#[async_trait::async_trait]
pub trait RenewalScheduler: Send + Sync {
    async fn run_once(&self) -> Result<()>;
}

/// Task priority for renewal
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
    Urgent = 3,
}

/// A renewal task
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RenewalTask {
    pub domains: Vec<String>,
    pub priority: Priority,
    pub retry_count: u32,
}

impl Ord for RenewalTask {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for RenewalTask {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Advanced renewal scheduler with concurrency and priority support
#[derive(Clone)]
pub struct AdvancedRenewalScheduler<B: StorageBackend> {
    client: AcmeClient,
    store: CertificateStore<B>,
    hook: Option<Arc<dyn RenewalHook>>,
    concurrency: usize,
    queue: Arc<Mutex<BinaryHeap<RenewalTask>>>,
    notifier: Arc<Notify>,
    task_tx: mpsc::Sender<RenewalTask>,
}

impl<B: StorageBackend + 'static> AdvancedRenewalScheduler<B> {
    pub fn new(
        client: AcmeClient,
        store: CertificateStore<B>,
        concurrency: usize,
    ) -> (Self, TaskSender) {
        let queue = Arc::new(Mutex::new(BinaryHeap::new()));
        let notifier = Arc::new(Notify::new());
        let (tx, mut rx) = mpsc::channel::<RenewalTask>(100);

        let q_clone = queue.clone();
        let n_clone = notifier.clone();

        // Background proxy to bridge channel and priority heap
        tokio::spawn(async move {
            while let Some(task) = rx.recv().await {
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

    pub fn with_hook(mut self, hook: Arc<dyn RenewalHook>) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Run all pending renewals once
    pub async fn run_once_internal(&self) -> Result<()> {
        info!("Running full renewal check...");
        // Here we would iterate over all managed certificates and enqueue those due for renewal
        // For demonstration, we trigger a scan of the store
        let certs = self.store.list_all().await?;
        for cert in certs {
            // Check if due... simplified: enqueue everything for demo
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

    /// Start the scheduler
    pub async fn run(self: Arc<Self>) {
        info!(
            "Starting Advanced Renewal Scheduler with concurrency: {}",
            self.concurrency
        );
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrency));
        let scheduler_arc = self;

        loop {
            // Wait for tasks
            {
                let q = scheduler_arc.queue.lock().await;
                if q.is_empty() {
                    drop(q);
                    scheduler_arc.notifier.notified().await;
                    continue;
                }
            }

            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let task = {
                let mut q = scheduler_arc.queue.lock().await;
                q.pop().unwrap()
            };

            let s = scheduler_arc.clone();
            tokio::spawn(async move {
                let _permit = permit;
                info!(
                    "Processing renewal task (Priority: {:?}) for domains: {:?}",
                    task.priority, task.domains
                );

                if let Some(h) = &s.hook {
                    h.before_renewal(&task.domains);
                }

                // Clone client for each task to allow concurrent mutable access
                let mut client = s.client.clone();
                match Self::perform_renewal(&mut client, &s.store, &task.domains).await {
                    Ok(bundle) => {
                        info!("Successfully renewed certificate for {:?}", task.domains);
                        if let Some(h) = &s.hook {
                            h.after_renewal(&task.domains, &bundle);
                        }
                    }
                    Err(e) => {
                        error!("Failed to renew certificate for {:?}: {}", task.domains, e);
                        if let Some(h) = &s.hook {
                            h.on_error(&task.domains, &e);
                        }

                        if task.retry_count < 3 {
                            let mut next_task = task.clone();
                            next_task.retry_count += 1;
                            warn!(
                                "Retrying task for {:?} (attempt {})",
                                task.domains, next_task.retry_count
                            );
                            let _ = s.task_tx.send(next_task).await;
                        }
                    }
                }
            });
        }
    }

    async fn perform_renewal(
        client: &mut AcmeClient,
        _store: &CertificateStore<B>,
        domains: &[String],
    ) -> Result<CertificateBundle> {
        // Use CertificateProvisioner to handle the actual renewal logic
        // This is a simplified version for the scheduler
        let mut registry = ChallengeSolverRegistry::new();
        registry.register(Http01Solver::default()); // Default to HTTP-01 for now

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

pub type TaskSender = mpsc::Sender<RenewalTask>;
