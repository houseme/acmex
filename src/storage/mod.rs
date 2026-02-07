pub mod cert_store;
pub mod encrypted;
/// Storage backends for certificates and account data
pub mod file;
#[cfg(feature = "redis")]
pub mod redis;

use crate::error::Result;
use async_trait::async_trait;

/// Storage backend trait
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store a value by key
    async fn store(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Load a value by key
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Delete a value by key
    async fn delete(&self, key: &str) -> Result<()>;

    /// List keys by prefix
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

pub use cert_store::CertificateStore;
pub use encrypted::EncryptedStorage;
pub use file::FileStorage;
#[cfg(feature = "redis")]
pub use redis::RedisStorage;
