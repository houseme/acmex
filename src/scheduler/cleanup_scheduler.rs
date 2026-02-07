use crate::error::Result;
use crate::storage::StorageBackend;
use std::time::Duration;
use tracing::{error, info, warn};
use x509_parser::prelude::*;

/// Scheduler for cleaning up expired certificates and temporary data
pub struct CleanupScheduler<B: StorageBackend> {
    backend: B,
    interval: Duration,
}

impl<B: StorageBackend> CleanupScheduler<B> {
    pub fn new(backend: B, interval: Duration) -> Self {
        Self { backend, interval }
    }

    /// Start the cleanup loop
    pub async fn run(self) -> Result<()> {
        info!(
            "Starting Cleanup Scheduler with interval: {:?}",
            self.interval
        );
        let mut interval = tokio::time::interval(self.interval);

        loop {
            interval.tick().await;
            if let Err(e) = self.perform_cleanup().await {
                error!("Cleanup task failed: {}", e);
            }
        }
    }

    async fn perform_cleanup(&self) -> Result<()> {
        info!("Performing scheduled cleanup...");

        // 1. 获取所有证书 key (前缀应与 CertificateStore 一致)
        let keys = self.backend.list("cert:").await?;
        let mut removed_count = 0;

        for key in keys {
            if let Some(data) = self.backend.load(&key).await? {
                // 尝试解析证书
                if let Ok((_, x509)) = parse_x509_certificate(&data) {
                    let now = jiff::Zoned::now();
                    let not_after = x509.validity().not_after;

                    // 检查是否过期
                    if not_after.timestamp() < now.timestamp().as_second() {
                        info!("Removing expired certificate: {}", key);
                        self.backend.delete(&key).await?;
                        removed_count += 1;
                    }
                } else {
                    warn!(
                        "Failed to parse certificate data for key: {}, skipping",
                        key
                    );
                }
            }
        }

        if removed_count > 0 {
            info!(
                "Cleanup completed. Removed {} expired certificates.",
                removed_count
            );
        } else {
            info!("Cleanup completed. No expired certificates found.");
        }

        Ok(())
    }
}
