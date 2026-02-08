/// Storage backends for certificates, account data, and session state.
/// This module provides a pluggable storage architecture with support for
/// local files, Redis, in-memory, and encrypted wrappers.
pub mod cert_store;
pub mod encrypted;
pub mod file;
pub mod memory;
pub mod migration;

#[cfg(feature = "redis")]
pub mod redis;

use crate::error::Result;
use async_trait::async_trait;

/// A trait defining the interface for all storage backends.
/// Implementations must be thread-safe and support asynchronous operations.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Stores a binary value associated with the given key.
    async fn store(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Loads a binary value by its key. Returns `None` if the key does not exist.
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Deletes the value associated with the given key.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Lists all keys that start with the specified prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// Blanket implementation for `Arc<T>` to allow easy sharing of storage backends.
#[async_trait]
impl<T: StorageBackend + ?Sized> StorageBackend for std::sync::Arc<T> {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        (**self).store(key, value).await
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        (**self).load(key).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        (**self).delete(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        (**self).list(prefix).await
    }
}

pub use cert_store::CertificateStore;
pub use encrypted::EncryptedStorage;
pub use file::FileStorage;
pub use memory::MemoryStorage;
pub use migration::StorageMigrator;
#[cfg(feature = "redis")]
pub use redis::RedisStorage;
