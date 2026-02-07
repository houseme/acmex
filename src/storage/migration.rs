use crate::error::Result;
use crate::storage::StorageBackend;
use tracing::info;

/// Utility for migrating data between different storage backends
pub struct StorageMigrator<S: StorageBackend, D: StorageBackend> {
    source: S,
    destination: D,
}

impl<S: StorageBackend, D: StorageBackend> StorageMigrator<S, D> {
    pub fn new(source: S, destination: D) -> Self {
        Self { source, destination }
    }

    /// Migrate all data from source to destination
    pub async fn migrate(&self) -> Result<()> {
        info!("Starting storage migration...");
        // 1. 获取源存储中所有的 key
        let keys = self.source.list("").await?;
        info!("Found {} items to migrate", keys.len());

        let mut success_count = 0;
        let mut fail_count = 0;

        for key in keys {
            match self.source.load(&key).await {
                Ok(Some(data)) => {
                    if let Err(e) = self.destination.store(&key, &data).await {
                        tracing::error!("Failed to store key {}: {}", key, e);
                        fail_count += 1;
                    } else {
                        success_count += 1;
                        tracing::debug!("Successfully migrated key: {}", key);
                    }
                }
                Ok(None) => {
                    tracing::warn!("Key {} vanished during migration", key);
                }
                Err(e) => {
                    tracing::error!("Failed to load key {}: {}", key, e);
                    fail_count += 1;
                }
            }
        }

        info!("Migration completed. Success: {}, Failed: {}", success_count, fail_count);
        if fail_count > 0 {
            return Err(crate::error::AcmeError::Storage(format!("Migration finished with {} errors", fail_count)));
        }
        Ok(())
    }
}
